# CODoH Project Overview

## Goal

**CODoH (Cached Oblivious DNS over HTTPS)** extends ODoH (RFC 9230) with proxy-side caching while preserving privacy guarantees. The key insight: use VOPRF-based blind tokens to enable caching without revealing query patterns to the proxy.

**Problem**: Standard ODoH uses per-query ephemeral keys, preventing caching at the proxy. Every query hits the target.

**Solution**: Clients obtain blind tokens from target, include them in an encrypted blob to the enclave, which verifies tokens and serves cached responses.

---

## Architecture

```
+---------------------------------------------------------------------------+
|                              PROXY HOST                                   |
|                                                                           |
|   +--------------------+            +-------------------------------+     |
|   |   Proxy (CoreDNS)  |   Unix     |   Enclave (EGo/SGX)           |     |
|   |   plugin/codohproxy|   Socket   |   enclave/                    |     |
|   |                    |<---------->|                               |     |
|   |   - /proxy         |    IPC     |   - Token verification (VOPRF)|     |
|   |   - /enclave-keys  |            |   - Spent-set (double-spend)  |     |
|   |   - TLS termination|            |   - LRU Cache (DNS responses) |     |
|   |   - Bypass mode    |            |   - HPKE decrypt Blob B       |     |
|   |                    |            |   - Signature verification    |     |
|   +---------+----------+            +---------------+---------------+     |
+-----------+---------------------------------+------+----------------------+
            | HTTPS                           |
            v                                 | HTTPS (Attestation)
    +-------------------+                     |
    |   Target (CoreDNS)|<--------------------+
    | plugin/codohtarget|   POST /provision (encrypted master_secret + signing_pubkey)
    |                   |   GET /attest (quote + pk_E)
    |   - /dns-query    | ODoH resolution
    |   - /token        | Batch token issuance (VOPRF)
    |   - /.well-known/odohconfigs | ODoH public key
    |   - /verify       | Token verification (fallback)
    |   - Response signing (Ed25519)
    +-------------------+
            |
            v DNS (UDP)
        Upstream (8.8.8.8)
```

---

## Components

| Component | Location | Technology | Role |
|-----------|----------|------------|------|
| **Client** | codoh-client/ | Go CLI | Query originator, token holder, Blob B creator |
| **Proxy** | plugin/codohproxy | CoreDNS plugin | Network I/O, enclave IPC, bypass fallback |
| **Enclave** | enclave/ | Go (EGo for SGX) | Token verification, cache, spent-set, signature verification |
| **Target** | plugin/codohtarget | CoreDNS plugin | Token issuance, DNS resolution, response signing, secret provisioning |

---

## Protocol Flow

### Attestation & Provisioning (on startup, SGX mode)

```
Target                         Enclave
   |                              |
   |---- GET /attest ------------>|  (request quote + pubkey)
   |                              |  Generate DCAP quote binding pk_E
   |<--- {quote, pk_E} -----------|
   |                              |
   |  Verify SGX quote            |
   |  Verify MRSIGNER (optional)  |
   |                              |
   |  Encrypt master_secret       |
   |  under pk_E (HPKE)           |
   |                              |
   |-- POST /provision ---------->|  {encrypted_secret, signing_pubkey}
   |                              |  Decrypt master_secret
   |                              |  Store signing_pubkey
   |<--- OK ----------------------|
   |                              |
   |  Both now have same          |
   |  master_secret for VOPRF     |
```

### Token Issuance (once per epoch)

```
Client                          Target
   |                               |
   |---- POST /token ------------->|  (count + blinded elements)
   |                               |  Rate limit check (per-IP)
   |<--- VOPRF evaluations --------|  (evaluated elements)
   |                               |
   |  Finalize tokens locally      |
   |  tokens = [(epoch, input, output), ...]
```

### Query Flow (per DNS query)

```
Client              Proxy                 Enclave              Target
   |                   |                     |                    |
   |  B = Enc(pk_E, epoch||input||token||k_c||query)              |
   |                   |                     |                    |
   |-- ODoH + B ------>|                     |                    |
   |                   |-- Process(B) ------>|                    |
   |                   |                     | Decrypt B          |
   |                   |                     | Verify token       |
   |                   |                     | Mark spent         |
   |                   |                     | Check cache        |
   |                   |                     |                    |
   |                   |<-- HIT: Enc(k_c, resp)                   |
   |<-- cached resp ---|                     |                    |
   |                   |                     |                    |
   |   -- OR --        |                     |                    |
   |                   |<-- MISS ------------|                    |
   |                   |                     |                    |
   |                   |-- ODoH + X-Enclave-PubKey + X-ODoH-Blob ->|
   |                   |                     |                    |
   |                   |<-- ODoH response -------------------------|
   |                   |    + X-Enclave-Cache: Enc(pk_E, raw_dns)  |
   |                   |    + X-Enclave-Cache-Sig: Sign(H(resp||query||B))
   |                   |                     |                    |
   |                   |-- StoreEncrypted -->| Verify signature   |
   |                   |   (cache + sig + B) | Decrypt with sk_E  |
   |                   |                     | Cache raw DNS      |
   |                   |                     |                    |
   |<-- ODoH response -|                     |                    |
```

---

## Key Data Structures

### Blob B (Client -> Enclave)

```
B = HPKE.Seal(pk_E, plaintext)

plaintext = epoch (4B) || input (32B) || token (32B) || k_c (32B) || query (var)
          = 100 + len(query) bytes minimum
```

### Token Format

```
Token = epoch (4 bytes) || input (32 bytes)
      = 36 bytes

Verification: OPRF.FullEvaluate(epoch_key, input) == output
```

### Cache Response Signature

```
signature = Ed25519.Sign(target_sk, H(response || query || blobB))

Verification: Ed25519.Verify(target_pk, H(response || query || blobB), signature)
```

### IPC Protocol (Unix Socket)

```
[4 bytes: length (big-endian)][JSON payload]

Request types:  process, store_encrypted, get_pubkey, health, ready
Response status: hit, miss, error, ok
```

---

## Cryptographic Primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| VOPRF | P-256 (NIST curve) | cloudflare/circl/oprf |
| HPKE | DHKEM(X25519, HKDF-SHA256) + AES-128-GCM | cloudflare/circl/hpke |
| Cache encryption | AES-128-GCM | cloudflare/circl/hpke (AEAD) |
| Key derivation | HKDF-SHA256 (via OPRF.DeriveKey) | cloudflare/circl |
| Response signing | Ed25519 | Go stdlib crypto/ed25519 |
| SGX attestation | DCAP | edgelesssys/ego |

---

## Implementation Status

### Done (Phase 2a-2f)

| Component | Files | Status |
|-----------|-------|--------|
| **Enclave Core** | | |
| HPKE keypair, encrypt/decrypt | enclave/crypto.go | Done |
| IPC server (Unix socket) | enclave/ipc.go | Done |
| Token verification (VOPRF) | enclave/voprf.go | Done |
| Spent-set (double-spend) | enclave/spentset.go | Done |
| LRU cache with TTL | enclave/cache.go | Done |
| ORAM cache (Path ORAM) | enclave/oram_cache.go | Done |
| Cache interface | enclave/cache_interface.go | Done |
| Query canonicalization | enclave/query.go | Done |
| SGX attestation server | enclave/attestation.go | Done |
| SGX quote generation | enclave/attestation_sgx.go | Done |
| Simulation fallbacks | enclave/attestation_sim.go | Done |
| Configuration loading | enclave/config.go | Done |
| IPC types | enclave/types.go | Done |
| Main entry point | enclave/cmd/main.go | Done |
| | | |
| **Proxy** | | |
| Enclave IPC client | plugin/codohproxy/enclave_client.go | Done |
| Enclave-first flow | plugin/codohproxy/proxy.go | Done |
| /enclave-keys endpoint | plugin/codohproxy/proxy.go | Done |
| Bypass mode | plugin/codohproxy/proxy.go | Done |
| Forward blob B to target | plugin/codohproxy/proxy.go | Done |
| Forward signature to enclave | plugin/codohproxy/proxy.go | Done |
| Wait for enclave ready | plugin/codohproxy/proxy.go | Done |
| Prometheus metrics | plugin/codohproxy/metrics.go | Done |
| Config options | plugin/codohproxy/setup.go | Done |
| | | |
| **Target** | | |
| Token issuance (VOPRF) | plugin/codohtarget/voprf.go | Done |
| Rate limiting (per-IP) | plugin/codohtarget/ratelimit.go | Done |
| Master secret loading | plugin/codohtarget/target.go | Done |
| Enclave cache encryption | plugin/codohtarget/enclave_encrypt.go | Done |
| Ed25519 response signing | plugin/codohtarget/signing.go | Done |
| SGX quote verification | plugin/codohtarget/attestation_verify_sgx.go | Done |
| Simulation skip verification | plugin/codohtarget/attestation_verify_sim.go | Done |
| Secret provisioning | plugin/codohtarget/attestation.go | Done |
| Prometheus metrics | plugin/codohtarget/metrics.go | Done |
| Config options | plugin/codohtarget/setup.go | Done |
| | | |
| **Client** | | |
| Blob B encryption | codoh-client/commands/blob.go | Done |
| --enclave flag | codoh-client/commands/commands.go | Done |
| X-ODoH-Blob header | codoh-client/commands/request.go | Done |
| Token management | codoh-client/commands/tokens.go | Done |
| Latency benchmarking | codoh-client/commands/latency.go | Done |

### Deferred

(none) 

---

## Configuration

### Proxy Corefile

```
codohproxy {
    target https://target:8443/dns-query
    port 8080
    tls_cert /path/to/cert.pem
    tls_key /path/to/key.pem
    insecure_skip_verify true

    # Enclave
    enclave_enabled
    enclave_socket /tmp/codoh-enclave.sock
    enclave_bypass_on_failure true
}
```

### Target Corefile

```
codohtarget {
    port 8443
    tls_cert /path/to/cert.pem
    tls_key /path/to/key.pem
    upstream 8.8.8.8:53

    # Token issuance
    token_enabled
    epoch_duration 1h
    rate_limit 100
    master_secret /path/to/master-secret.txt

    # Response signing
    signing_key /path/to/signing-key.pem   # Ed25519, auto-generates if missing

    # SGX attestation (for provisioning to enclave)
    enclave_url https://localhost:8444
    enclave_mrsigner <expected_mrsigner_hex>   # Optional: verify enclave identity

    log_queries true   # Optional: log DNS queries
}
```

### Enclave Startup

```bash
# Development (no SGX) - uses file/env for master secret
cd enclave && go build -o enclave-dev ./cmd
CODOH_MASTER_SECRET=$(cat dev-master-secret.txt) ./enclave-dev --socket /tmp/codoh-enclave.sock

# Or with file argument
./enclave-dev --socket /tmp/codoh-enclave.sock --secret dev-master-secret.txt

# Production (SGX) - waits for provisioning from target
cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave
ego run enclave --socket /tmp/codoh-enclave.sock --https-port 8444
# (blocks until provisioned via /provision endpoint)
```

### Environment Variables (Enclave)

| Variable | Description | Default |
|----------|-------------|---------|
| CODOH_MASTER_SECRET | Hex-encoded 32-byte secret | Required in sim mode |
| CODOH_EPOCH_DURATION | Epoch duration in seconds | 3600 |
| CODOH_SOCKET_PATH | Unix socket path | /tmp/codoh-enclave.sock |
| CODOH_CACHE_SIZE | Cache entries | 10000 |
| CODOH_USE_ORAM | Enable ORAM cache | false |
| CODOH_ORAM_BLOCK_SIZE | ORAM block size (bytes) | 4096 |

### Client Usage

```bash
# Single query with enclave caching
./odoh-client odoh --domain example.com. --dnstype A \
  --target 127.0.0.1:8443 --proxy 127.0.0.1:8080 \
  --customcert proxy.pem --enclave

# Latency benchmark
./odoh-client latency \
  --protocol codoh \
  --distribution sequential \
  --iterations 1000 \
  --target 127.0.0.1:8443 \
  --proxy 127.0.0.1:8080 \
  --customcert localhost.pem \
  --domains benchmark/top-1m.csv \
  --output results.csv \
  --summary results.json
```

---

## File Structure

```
coredns/
├── enclave/                    # SGX enclave code
│   ├── cmd/main.go            # Entry point, handler implementation
│   ├── crypto.go              # HPKE keypair, encrypt/decrypt, BlobB parsing
│   ├── ipc.go                 # Unix socket server
│   ├── voprf.go               # Token verification, epoch keys
│   ├── spentset.go            # Double-spend tracking
│   ├── cache.go               # LRU cache with TTL
│   ├── cache_interface.go     # Cache interface
│   ├── oram_cache.go          # Path ORAM cache (access-pattern hiding)
│   ├── query.go               # Query canonicalization
│   ├── config.go              # Configuration loading (env/file)
│   ├── types.go               # IPC message types
│   ├── attestation.go         # HTTPS attestation server (/attest, /provision)
│   ├── attestation_sgx.go     # SGX-specific: quote generation, attested TLS
│   ├── attestation_sim.go     # Simulation fallbacks
│   └── enclave.json           # EGo manifest
│
├── plugin/
│   ├── codohproxy/            # Proxy plugin
│   │   ├── proxy.go           # Main handler, /proxy, /enclave-keys, /health
│   │   ├── enclave_client.go  # IPC client for enclave
│   │   ├── setup.go           # Corefile parsing
│   │   └── metrics.go         # Prometheus metrics
│   │
│   └── codohtarget/           # Target plugin
│       ├── target.go          # Main handler, /dns-query, /token, /verify
│       ├── voprf.go           # Epoch manager, token issuance
│       ├── ratelimit.go       # Per-IP rate limiting
│       ├── enclave_encrypt.go # HPKE encryption for cache
│       ├── signing.go         # Ed25519 response signing
│       ├── attestation.go     # Enclave provisioning client
│       ├── attestation_verify_sgx.go  # SGX quote verification (DCAP)
│       ├── attestation_verify_sim.go  # Simulation (skip verification)
│       ├── setup.go           # Corefile parsing
│       └── metrics.go         # Prometheus metrics
│
├── benchmark/                  # Benchmarking tools
│   ├── run-benchmark.sh       # Main benchmark script
│   ├── top-1m.csv             # Domain list for benchmarks
│   ├── Corefile.odoh-proxy    # ODoH baseline proxy config
│   └── Corefile.odoh-target   # ODoH baseline target config
│
└── codoh-client/              # Client (separate directory)
    └── commands/
        ├── blob.go            # BlobB struct, HPKE encryption
        ├── commands.go        # CLI flags (--enclave, --protocol)
        ├── request.go         # HTTP request construction
        ├── tokens.go          # Token management
        └── latency.go         # Latency benchmarking
```

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Query privacy from proxy | Blob B encrypted under pk_E |
| Token unlinkability | VOPRF blind tokens |
| Rate limiting (issuance) | Per-IP limits at target |
| Rate limiting (redemption) | Per-token spent-set in enclave |
| Replay protection | Spent-set marks tokens used |
| Epoch isolation | Tokens bound to epoch, spent-set cleared on rotation |
| Cache integrity | Target signs responses with Ed25519, enclave verifies |
| Request binding | Signature binds response to query and blob B |
| Secret provisioning | SGX attestation + HPKE encryption |

---

## Testing

### E2E Test (Development)

```bash
# Use the test script
./scripts/test-attestation-e2e.sh          # Simulation mode
./scripts/test-attestation-e2e.sh --sgx    # SGX hardware mode
```

### Benchmark

```bash
# Run full benchmark suite
./benchmark/run-benchmark.sh 100           # 100 iterations, simulation
./benchmark/run-benchmark.sh --sgx 1000    # 1000 iterations, SGX mode
```

### Manual Testing

```bash
# Terminal 1: Start enclave (simulation)
CODOH_MASTER_SECRET=$(cat dev-master-secret.txt) ./enclave-sim

# Terminal 2: Start target
./coredns -conf Corefile.target

# Terminal 3: Start proxy
./coredns -conf Corefile.proxy

# Terminal 4: Test
./odoh-client odoh --domain example.com. --dnstype A \
  --target 127.0.0.1:8443 --proxy 127.0.0.1:8080 \
  --customcert localhost.pem --enclave
```

### Verify Cache Hit

```bash
# First query (miss - goes to target)
./odoh-client odoh --domain example.com. --dnstype A --enclave ...

# Second query with new token (hit - served from enclave cache)
./odoh-client odoh --domain example.com. --dnstype A --enclave ...
```

---

## HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| X-ODoH-Blob | Client -> Proxy | Base64-encoded encrypted blob B |
| X-Enclave-PubKey | Proxy -> Target | Base64-encoded enclave HPKE public key |
| X-Enclave-Cache | Target -> Proxy | Base64-encoded HPKE-encrypted raw DNS response |
| X-Enclave-Cache-Sig | Target -> Proxy | Base64-encoded Ed25519 signature |
| X-Enclave-Cache-Query | Target -> Proxy | Canonicalized query string |

---

## Content Types

| Content-Type | Description |
|--------------|-------------|
| application/oblivious-dns-message | Standard ODoH (RFC 9230) |
| application/codoh-cached | Cached response from enclave (AES-GCM under k_c) |

---

## Next Steps

- MLE ciphertext-only cache (hide plaintext from enclave)
- Stochastic hit suppression / non-insertion
- Random churn eviction