# CODoH Project Overview

## Goal

**CODoH (Cached Oblivious DNS over HTTPS)** extends ODoH (RFC 9230) with privacy-preserving proxy-side caching. The cache lives inside an SGX enclave co-located with the proxy, using ORAM for access-pattern hiding and cover responses + batched insertions to resist set-difference attacks.

**Problem**: Standard ODoH uses per-query ephemeral keys, preventing caching at the proxy. Every query hits the target, negating the latency benefits of caching.

**Solution**: The client encrypts the query under both the target's and enclave's HPKE public keys. The enclave decrypts its copy to check the cache. On a miss, the target resolves the query, signs the response, and returns an HPKE-encrypted cache-insert blob for the enclave to store. On subsequent queries for the same domain, the enclave serves the cached response directly.

---

## Security Goals (from paper)

**G1 — Authorized and fresh cached answers**: A malicious proxy must not cause clients to accept DNS answers that the target did not authorize, or that are stale. Prevents cache poisoning, tampering, and stale-answer replay.

**G2 — Cache-state indistinguishability under active probing and scheduling**: The proxy must not learn meaningful information about a client's query by manipulating or comparing cache state across time. Prevents set-difference/bracketing attacks, cache priming, selective withholding, and restart-based reset windows.

**G3 — Query equality and profiling resistance**: The proxy must not determine whether two client requests correspond to the same DNS query, or build per-client/per-group query profiles from cache behavior.

### Primary Attack: Set-Difference (Bracketing)

1. Adversary learns current cache state
2. Allows exactly one victim query while queuing all other traffic
3. Re-learns cache state
4. Computes difference to isolate which entry was added or accessed

### Threat Model

In-scope adversary capabilities (beyond ODoH baseline):
- Network control at proxy: observe/delay/drop/replay/inject
- Active proxy deviation: arbitrary protocol deviation to bias cache behavior
- Scheduling control: manipulate concurrency and queuing to isolate victims
- Cache lifecycle control: restart enclave to reset cache state
- Proxy-as-client probing: send probe queries to enumerate cache contents
- Architectural leakage: page-level access patterns, gross timing differences, message size differences

Out-of-scope:
- Traffic correlation by a global adversary
- Website fingerprinting from client behavior patterns
- Microarchitectural attacks against TEE (Spectre/Meltdown class)
- Malicious target or proxy-target collusion

---

## Architecture

```
Client ──► Proxy ──► Target ──► Upstream DNS
              │
              ▼
           Enclave (SGX)
           - HPKE decryption
           - Response caching (LRU or ORAM)
           - Cache-insert verification (Ed25519)
           - Dummy responses (hit/miss indistinguishable)
```

### Components

| Component | Location | Technology | Role |
|-----------|----------|------------|------|
| **Client** | codoh-client/ | Go CLI | Query originator, Q_E + Q_T encryption |
| **Proxy** | plugin/codohproxy | CoreDNS plugin | Network I/O, enclave IPC, parallel fan-out |
| **Enclave** | enclave/ | Go (EGo for SGX) | Cache, HPKE decryption, signature verification |
| **Target** | plugin/codohtarget | CoreDNS plugin | DNS resolution, cache-insert encryption + signing |

---

## Protocol Flow

### Bootstrap (on startup)

1. Enclave generates HPKE keypair `(pk_E, sk_E)` and SGX attestation report binding `pk_E`
2. In SGX mode: target fetches `/attest` from enclave, verifies quote, POSTs Ed25519 signing pubkey to `/provision`
3. In simulation mode: enclave reads signing pubkey from `CODOH_TARGET_SIGNING_PUBKEY` env var
4. Client retrieves `pk_E` from proxy's `/enclave-keys` endpoint

### Query Flow (per DNS query)

```
Client              Proxy                 Enclave              Target
   |                   |                     |                    |
   |  Q_E = HPKE.Seal(pk_E, query)          |                    |
   |  Q_T = ODoH envelope (standard)        |                    |
   |                   |                     |                    |
   |-- Q_T + Q_E ----->|                     |                    |
   |  (X-CoDOH-Query)  |                     |                    |
   |                   |== parallel fan-out ==|                    |
   |                   |-- process(Q_E) ---->|                    |
   |                   |                     | Decrypt Q_E        |
   |                   |                     | Derive k_r (Export)|
   |                   |                     | Check cache        |
   |                   |                     |                    |
   |                   |-- Q_T + pk_E ------>|----> Target ------>|
   |                   |  (X-Enclave-PubKey) |                    |
   |                   |                     |                    |
   |                   |<-- HIT: Enc(k_r, resp) [or dummy on MISS]|
   |                   |                     |                    |
   |                   |<-- ODoH response + cache-insert headers -|
   |                   |    X-Enclave-Cache: HPKE.Seal(pk_E, bundle)
   |                   |    X-Enclave-Cache-Sig: Ed25519(H(bundle))
   |                   |                     |                    |
   |                   |-- store_encrypted ->| Verify Ed25519 sig |
   |                   |   (async, on miss)  | Validate timestamp |
   |                   |                     | Decrypt bundle     |
   |                   |                     | Enqueue for batch  |
   |                   |                     |                    |
   |<-- response ------|                     |                    |
   |  (hit: cached via k_r; miss: ODoH)     |                    |
```

**Key properties:**
- Proxy fans out Q_E to enclave and Q_T to target in parallel
- On cache miss, enclave returns a dummy response indistinguishable from a hit (same size)
- Client determines hit vs miss by Content-Type (`application/codoh-cached` vs `application/oblivious-dns-message`)
- Response key `k_r` is derived via HPKE Export from the Q_E context — implicitly bound to the ephemeral KEM key

### Cache-Insert Bundle

The target constructs and signs a bundle when `X-Enclave-PubKey` is present:

```
CacheInsertBundle = ttl (4B) || timestamp (8B) || query_len (2B) || canonical_query || dns_response

Encrypted: HPKE.Seal(pk_E, info="codoh-enclave-v2", bundle)
Signature: Ed25519.Sign(target_sk, SHA-256(bundle))
```

The enclave verifies the signature, validates the timestamp against a monotonic logical clock (`t_latest`), decrypts the bundle, and enqueues the plaintext DNS response for batched cache commit. Queued entries are committed to the cache probabilistically during `HandleProcess` calls (coin flip per query, `crypto/rand`).

### Replay Protection

SGX has no trusted clock. The enclave maintains `t_latest` (highest timestamp seen) and rejects bundles where `timestamp < t_latest - δ` (default δ = 3 seconds). This provides a grace window for legitimate message reordering while preventing replay of old responses.

---

## Cryptographic Primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| HPKE | DHKEM(X25519, HKDF-SHA256) + AES-128-GCM | cloudflare/circl/hpke |
| Response key derivation | HPKE Export (label: "codoh response", 16 bytes) | cloudflare/circl/hpke |
| Cache-insert encryption | HPKE to pk_E (info: "codoh-enclave-v2") | cloudflare/circl/hpke |
| Cached response encryption | AES-128-GCM under k_r (random nonce) | Go stdlib crypto/aes |
| Response signing | Ed25519 | Go stdlib crypto/ed25519 |
| SGX attestation | DCAP | edgelesssys/ego |
| Access-pattern hiding | Path ORAM | etclab/pathoram-go |

---

## Implementation Status

### Implemented

| Feature | Files | Notes |
|---------|-------|-------|
| **Enclave Core** | | |
| HPKE keypair + decrypt/encrypt | enclave/crypto.go | Suite: X25519/HKDF-SHA256/AES-128-GCM |
| HPKE Export key derivation (k_r) | enclave/crypto.go | Label: "codoh response" |
| IPC server (Unix socket) | enclave/ipc.go | 4-byte length + JSON wire protocol |
| LRU cache with logical-time TTL | enclave/cache.go | container/list, sync.RWMutex |
| ORAM cache (Path ORAM) | enclave/oram_cache.go | FNV hash mapping, lazy expiry |
| Cache interface | enclave/cache_interface.go | Get/Put/Size/Clear/CleanExpired |
| Cache-insert bundle format | enclave/bundle.go | ttl + timestamp + query + response |
| Ed25519 signature verification | enclave/cmd/main.go | On cache-insert bundles |
| Timestamp replay protection | enclave/cmd/main.go | Monotonic t_latest + δ-window |
| Dummy response generation | enclave/crypto.go | crypto/rand, same size as real |
| Query canonicalization | enclave/query.go | domain:qtype format |
| Configuration loading | enclave/config.go | Env vars + defaults |
| SGX attestation server | enclave/attestation.go | /attest, /provision, /health |
| SGX quote generation | enclave/attestation_sgx.go | EGo DCAP |
| Simulation fallbacks | enclave/attestation_sim.go | Self-signed TLS, skip quote |
| IPC message types | enclave/types.go | process, store_encrypted, get_pubkey, health |
| Proxy mode (CODoH-base) | enclave/cmd/proxy_mode.go | 2-process HTTPS server with LRU cache |
| Client-side HPKE helpers | enclave/client_crypto.go | EncryptQueryE, DecryptCachedResponse |
| Defensive mode (restart warm-up) | enclave/cmd/main.go | Starts in defensive mode, exits at WarmupThreshold |
| Cache omission detection | enclave/cmd/main.go | Outstanding query tracking, enters defensive mode at OmissionThreshold |
| Outstanding query TTL cleanup | enclave/cmd/main.go | Inline eviction using logical time (tLatest - OutstandingTTLSecs) |
| Key rotation signaling | enclave/cmd/main.go, enclave/types.go | HPKE failure returns `key_rotated` status |
| Health with restart metadata | enclave/cmd/main.go | `started_at` (RFC3339) in health response |
| Batched cache updates | enclave/insertion_queue.go, enclave/cmd/main.go | Bounded FIFO queue, pseudorandom batch commit on query path (crypto/rand), PutBatch on Cache interface |
| | | |
| **Proxy Plugin** | | |
| Parallel fan-out (enclave + target) | plugin/codohproxy/proxy.go | Concurrent goroutines |
| /enclave-keys endpoint | plugin/codohproxy/proxy.go | Serves pk_E |
| /proxy endpoint | plugin/codohproxy/proxy.go | Main CODoH relay |
| Enclave IPC client | plugin/codohproxy/enclave_client.go | Unix socket client |
| Key rotation header forwarding | plugin/codohproxy/proxy.go | Sets X-CoDOH-Key-Rotated header on key_rotated status |
| Bypass mode | plugin/codohproxy/proxy.go | Falls back to plain ODoH |
| Prometheus metrics | plugin/codohproxy/metrics.go | |
| Config options | plugin/codohproxy/setup.go | Corefile parsing |
| | | |
| **Target Plugin** | | |
| ODoH DNS resolution | plugin/codohtarget/target.go | /dns-query endpoint |
| Cache-insert HPKE encryption | plugin/codohtarget/enclave_encrypt.go | Encrypts bundle to pk_E |
| Ed25519 response signing | plugin/codohtarget/signing.go | Signs H(plaintext bundle) |
| SGX quote verification | plugin/codohtarget/attestation_verify_sgx.go | DCAP verification |
| Signing key provisioning | plugin/codohtarget/attestation.go | POST to /provision |
| Prometheus metrics | plugin/codohtarget/metrics.go | |
| Config options | plugin/codohtarget/setup.go | Corefile parsing |

### Paper Defenses Status

| Defense | Goal | Status | Notes |
|---------|------|--------|-------|
| HPKE query encryption (pk_E) | G3 | Done | Query privacy from proxy |
| Ed25519 cache-insert signing | G1 | Done | Prevents cache poisoning/tampering |
| Timestamp replay protection | G1 | Done | Monotonic t_latest + δ-window |
| Hit/miss dummy responses | G2, G3 | Done | Indistinguishable to proxy |
| ORAM cache | G2 | Done | Path ORAM, optional via config |
| SGX attestation + provisioning | G1 | Done | DCAP quote, signing key delivery |
| Restart warm-up mode | G2 | Done | Defensive mode on boot, exits at WarmupThreshold |
| Cache omission detection | G2 | Done | Outstanding query tracking, enters defensive mode at OmissionThreshold |
| Cover responses | G2 | Not yet | Target returns k random domains per cache-insert |
| Batched cache insertions | G2 | Done | InsertionQueue + pseudorandom commit via crypto/rand coin flip on query path |
| Session ID (sid) binding | G3 | Not yet | Explicit sid in AAD to prevent cross-use |
| Dual HPKE key wrapping | G3 | Not yet | Symmetric key k encrypted separately to target and enclave |

### Implementation-Only Features (not in paper)

| Feature | Notes |
|---------|-------|
| Key rotation signaling | `key_rotated` IPC status + `X-CoDOH-Key-Rotated` header. Paper says enclave "returns a key error" on restart but specifies no protocol for it. Key distribution is explicitly out of scope in the paper. |

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

    # Response signing
    signing_key /path/to/signing-key.pem   # Ed25519, auto-generates if missing

    # SGX attestation (for provisioning to enclave)
    enclave_url https://localhost:8444
    enclave_mrsigner <expected_mrsigner_hex>   # Optional: verify enclave identity

    log_queries true   # Optional
}
```

### Enclave Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| CODOH_CACHE_SIZE | 10000 | Number of cache entries |
| CODOH_USE_ORAM | false | Use ORAM cache instead of LRU |
| CODOH_ORAM_BLOCK_SIZE | 4096 | ORAM block size in bytes |
| CODOH_DEFAULT_PAD_SIZE | 512 | Dummy response size in bytes |
| CODOH_REPLAY_DELTA_SECS | 3.0 | Timestamp replay window (seconds) |
| CODOH_TARGET_SIGNING_PUBKEY | - | Base64 Ed25519 pubkey (sim mode only) |
| CODOH_WARMUP_THRESHOLD | 100 | Cache entries needed to exit defensive mode |
| CODOH_OMISSION_THRESHOLD | 50 | Outstanding queries to trigger defensive mode |
| CODOH_OUTSTANDING_TTL_SECS | 300 | Logical-time window (seconds) for outstanding query eviction |
| CODOH_BATCH_SIZE | 10 | Entries per batch commit |
| CODOH_BATCH_COMMIT_PROB | 0.1 | Probability of batch commit per HandleProcess call |
| CODOH_QUEUE_MAX_SIZE | 1000 | Max pending inserts in the insertion queue |

---

## HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| X-CoDOH-Query | Client -> Proxy | Base64-encoded Q_E (HPKE-encrypted query) |
| X-Enclave-PubKey | Proxy -> Target | Base64-encoded enclave HPKE public key |
| X-Enclave-Cache | Target -> Proxy | Base64-encoded HPKE-encrypted cache-insert bundle |
| X-Enclave-Cache-Sig | Target -> Proxy | Base64-encoded Ed25519 signature |
| X-Enclave-Cache-TTL | Target -> Proxy | TTL in seconds for cache entry |
| X-CoDOH-Key-Rotated | Proxy -> Client | `true` when enclave pk_E has rotated; client should re-fetch from `/enclave-keys` |
| X-CoDOH-Enclave-Error | Proxy -> Client | Error code when enclave leg fails (e.g., `key_rotated`, `enclave_unavailable`) |

## Content Types

| Content-Type | Description |
|--------------|-------------|
| application/oblivious-dns-message | Standard ODoH (RFC 9230) |
| application/codoh-cached | Cached response from enclave (AES-GCM under k_r) |

---

## IPC Protocol (Unix Socket)

```
Wire format: [4 bytes: length (big-endian)][JSON payload]

Request types:  process, store_encrypted, get_pubkey, health
Response status: hit, miss, error, ok, key_rotated
```

---

## Operating Modes

### IPC Mode (Configs 4-7) — 3-process architecture

```
Client → Proxy (codohproxy plugin) → Target (codohtarget plugin) → Upstream DNS
            │
            ▼
         Enclave (IPC over Unix socket)
```

Default mode. Enclave runs as a separate process communicating via Unix socket.

### Proxy Mode (Config 3, CODoH-base) — 2-process architecture

```
Client → Proxy (HTTPS, built-in cache) → ODoH Target → Upstream DNS
```

Single HTTPS proxy with HPKE keypair and LRU cache. No IPC, no signatures. Run with `enclave-sim -mode proxy`.

---

## File Structure

```
coredns/
├── enclave/                    # SGX enclave code
│   ├── cmd/main.go            # Entry point, EnclaveHandler, mode routing
│   ├── cmd/proxy_mode.go      # ProxyServer for CODoH-base
│   ├── crypto.go              # HPKE keypair, decrypt, encrypt, k_r derivation, dummy response
│   ├── client_crypto.go       # Client-side HPKE helpers (EncryptQueryE, DecryptCachedResponse)
│   ├── bundle.go              # CacheInsertBundle marshal/parse
│   ├── ipc.go                 # Unix socket server
│   ├── cache.go               # LRU cache with logical-time TTL
│   ├── cache_interface.go     # Cache interface (Get/Put/PutBatch/Size/Clear/CleanExpired)
│   ├── oram_cache.go          # Path ORAM cache (access-pattern hiding)
│   ├── insertion_queue.go     # Bounded FIFO queue for batched cache inserts
│   ├── query.go               # Query canonicalization
│   ├── config.go              # Configuration loading (env vars)
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
│       ├── target.go          # Main handler, /dns-query
│       ├── enclave_encrypt.go # HPKE encryption for cache-insert bundles
│       ├── signing.go         # Ed25519 response signing
│       ├── attestation.go     # Enclave provisioning client
│       ├── attestation_verify_sgx.go  # SGX quote verification (DCAP)
│       ├── attestation_verify_sim.go  # Simulation (skip verification)
│       ├── setup.go           # Corefile parsing
│       └── metrics.go         # Prometheus metrics
│
├── benchmark/                  # Benchmarking tools
│   ├── configs/{1..7}-*.sh    # Config profiles (sourceable)
│   ├── run-all.sh             # Multi-config orchestrator
│   └── top-1m.csv             # Domain list
│
└── codoh-client/              # Client (separate repo)
    └── commands/
        ├── blob.go            # Q_E encryption (HPKE)
        ├── commands.go        # CLI flags (--protocol codoh)
        ├── enclave_state.go   # pk_E caching + refresh on key rotation
        ├── request.go         # HTTP request construction
        └── latency.go         # Latency benchmarking
```

---

## Testing

### E2E Test (Development)

```bash
./scripts/test-attestation-e2e.sh          # Simulation mode
./scripts/test-attestation-e2e.sh --sgx    # SGX hardware mode
```

### Benchmarking

```bash
# Run all configs
./benchmark/run-all.sh

# Quick mode (100 iterations, cold only)
./benchmark/run-all.sh --quick

# Specific configs
./benchmark/run-all.sh --configs 1,3,4,5
```

### Manual Testing

```bash
# Terminal 1: Start enclave (simulation)
./enclave-sim --socket /tmp/codoh-enclave.sock

# Terminal 2: Start target
./coredns -conf Corefile.target

# Terminal 3: Start proxy
./coredns -conf Corefile.proxy

# Terminal 4: Test
cd ../codoh-client
./odoh-client latency --protocol codoh \
  --target 127.0.0.1:8443 --proxy 127.0.0.1:8080 \
  --customcert ../coredns/localhost.pem \
  --domains ../coredns/benchmark/top-1m.csv --iterations 10
```