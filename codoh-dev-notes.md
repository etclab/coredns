# CODoH CoreDNS Plugins

Implementation of Cached Oblivious DNS over HTTPS (CODoH), extending RFC 9230 ODoH with:
- VOPRF-based token issuance for rate limiting
- SGX enclave for secure token verification and response caching
- Remote attestation for secure secret provisioning

## Architecture

```
Client ──► Proxy ──► Target ──► Upstream DNS
              │
              ▼
           Enclave (SGX)
           - Token verification
           - Response caching
           - Blob B decryption
```

## Plugins

- **codohtarget**: ODoH target with VOPRF token issuance, enclave provisioning
- **codohproxy**: ODoH proxy with enclave integration for token verification/caching
- **odohtarget**: Basic ODoH target (RFC 9230)
- **odohproxy**: Basic ODoH proxy (RFC 9230)

## Quick Start

### Generate TLS Certs

```bash
# macOS
brew install mkcert
mkcert -install
mkcert -key-file localhost-key.pem -cert-file localhost.pem localhost 127.0.0.1

# Linux (alternative)
openssl req -x509 -newkey rsa:2048 -keyout localhost-key.pem -out localhost.pem \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### Build

```bash
go generate && go build
```

### Build Enclave

```bash
# Simulation mode (no SGX hardware)
cd enclave && go build -o enclave-sim ./cmd

# SGX mode (requires EGo SDK)
cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave
```

---

## Automated Testing

### Full E2E Test (Simulation)

Runs enclave + target + proxy + client query automatically:

```bash
./scripts/test-attestation-e2e.sh
```

### Full E2E Test (SGX Hardware)

Requires SGX hardware, EGo SDK, and PCCS configured:

```bash
./scripts/test-attestation-e2e.sh --sgx
```

### Enclave Provisioning Test

Quick test for enclave startup and IPC:

```bash
./scripts/test-provisioning.sh
```

---

## Manual Testing

### 1. Create Master Secret

```bash
# 32 bytes, hex-encoded (64 chars)
echo -n "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" > dev-master-secret.txt
```

### 2. Start Enclave (Simulation)

```bash
cd enclave
./enclave-sim --socket /tmp/codoh-enclave.sock --secret ../dev-master-secret.txt
```

### 3. Start Target

Using `Corefile.target`:
```
.:5354 {
    codohtarget {
        port 8443
        tls_cert localhost.pem
        tls_key localhost-key.pem
        upstream 8.8.8.8:53
        token_enabled
        epoch_duration 1h
        rate_limit 100
        master_secret dev-master-secret.txt
    }
}
```

```bash
./coredns -conf Corefile.target
```

### 4. Start Proxy

Using `Corefile.proxy`:
```
.:5353 {
    codohproxy {
        target https://127.0.0.1:8443/dns-query
        port 8080
        tls_cert localhost.pem
        tls_key localhost-key.pem
        insecure_skip_verify true
        enclave_enabled
        enclave_socket /tmp/codoh-enclave.sock
        enclave_bypass_on_failure true
    }
}
```

```bash
./coredns -conf Corefile.proxy
```

### 5. Test with odoh-client

```bash
cd ../codoh-client

# Basic ODoH query
./odoh-client odoh --domain example.com. --dnstype A \
    --target localhost:8443 \
    --proxy localhost:8080 \
    --customcert ../coredns/localhost.pem

# CODoH query (with enclave)
./odoh-client odoh --domain example.com. --dnstype A \
    --target localhost:8443 \
    --proxy localhost:8080 \
    --enclave \
    --customcert ../coredns/localhost.pem
```

---

## Endpoints

### Target (default :8443)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/odohconfigs` | GET | HPKE public key config |
| `/dns-query` | POST | ODoH query endpoint |
| `/token` | POST | VOPRF token issuance |
| `/verify` | POST | Token verification (fallback) |
| `/health` | GET | Health check |

### Proxy (default :8080)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/proxy` | POST | ODoH relay endpoint |
| `/enclave-keys` | GET | Enclave public key (for blob B) |
| `/health` | GET | Health check |

### Enclave (IPC + HTTPS in SGX mode)

| Endpoint | Description |
|----------|-------------|
| IPC: `process` | Verify token, decrypt blob B, check cache |
| IPC: `store_encrypted` | Store HPKE-encrypted response with signature verification |
| IPC: `get_pubkey` | Get enclave's HPKE public key |
| IPC: `health` | Health check |
| IPC: `ready` | Check if enclave is provisioned |
| HTTPS: `/attest` | Get SGX quote + public key |
| HTTPS: `/provision` | Receive encrypted master secret + signing pubkey |
| HTTPS: `/health` | Health check |

---

## HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-ODoH-Blob` | Client -> Proxy | Base64-encoded encrypted blob B |
| `X-Enclave-PubKey` | Proxy -> Target | Base64-encoded enclave HPKE public key |
| `X-Enclave-Cache` | Target -> Proxy | Base64-encoded HPKE-encrypted raw DNS response |
| `X-Enclave-Cache-Sig` | Target -> Proxy | Base64-encoded Ed25519 signature |
| `X-Enclave-Cache-Query` | Target -> Proxy | Canonicalized query string |

---

## SGX Mode

### Requirements

1. Intel SGX hardware with DCAP support
2. EGo SDK installed
3. User in `sgx` and `sgx_prv` groups:
   ```bash
   sudo usermod -aG sgx $USER
   sudo usermod -aG sgx_prv $USER
   ```
4. PCCS configured in `/etc/sgx_default_qcnl.conf`:
   ```json
    //PCCS server address
    //"pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/"
    "pccs_url": "https://localhost:8081/sgx/certification/v4/"
    // To accept insecure HTTPS certificate, set this option to false
    ,"use_secure_cert": false
   ```

### SGX Build & Run

```bash
cd enclave
ego-go build -tags ego -o enclave ./cmd
ego sign enclave
ego run enclave --socket /tmp/codoh-enclave.sock --https-port 8444
```

### Target with Enclave Provisioning

```
codohtarget {
    ...
    master_secret /path/to/secret.txt
    enclave_url https://proxy-host:8444
    enclave_mrsigner <64 hex chars>  # optional, from: ego signerid private.pem
}
```

---

## Configuration Reference

### codohtarget

| Directive | Description | Default |
|-----------|-------------|---------|
| `port` | HTTPS listen port | 8443 |
| `tls_cert` | TLS certificate path | required |
| `tls_key` | TLS private key path | required |
| `upstream` | Upstream DNS resolver | 8.8.8.8:53 |
| `token_enabled` | Enable VOPRF tokens | false |
| `epoch_duration` | Token epoch duration | 1h |
| `rate_limit` | Tokens per IP per epoch | 10 |
| `master_secret` | Path to 32-byte hex secret | - |
| `signing_key` | Path to Ed25519 signing key (auto-generates if missing) | - |
| `enclave_url` | Enclave HTTPS URL (SGX mode) | - |
| `enclave_mrsigner` | Expected MRSIGNER (SGX mode) | - |
| `log_queries` | Log DNS queries | false |

### codohproxy

| Directive | Description | Default |
|-----------|-------------|---------|
| `port` | HTTPS listen port | 8080 |
| `target` | Target URL | required |
| `tls_cert` | TLS certificate path | required |
| `tls_key` | TLS private key path | required |
| `insecure_skip_verify` | Skip target TLS verification | false |
| `enclave_enabled` | Enable enclave integration | false |
| `enclave_socket` | Enclave IPC socket path | /tmp/codoh-enclave.sock |
| `enclave_bypass_on_failure` | Continue without enclave if unavailable | true |

---

## What's Implemented

### CODoH-base (Proxy Mode, Config 3)

Minimal upgrade from ODoH: adds enclave-based LRU caching with a simplified blob, no tokens, no signatures, no IPC. 2-process architecture.

```
Client → Enclave-Proxy (HTTPS) → ODoH Target → Upstream DNS
```

**Processes:**

1. **ODoH Target** (`codohtarget` plugin, port 10444) — standard ODoH target, returns `X-Enclave-Cache` header with HPKE-encrypted raw DNS response
2. **Enclave-Proxy** (`enclave-sim -mode proxy`, port 10443) — HTTPS server with LRU cache, HPKE keypair, blob decryption

**Simplified Blob B format:** `kc (32 bytes) || canonical_query (variable)`
- No token, no epoch — client just encrypts kc + query under enclave's HPKE public key
- Enclave decrypts, looks up cache by query, encrypts cached response with kc on hit

**Flow (miss):**
1. Client fetches enclave public key from `/enclave-keys`
2. Client encrypts blob B (kc + query) under enclave pubkey
3. Client sends ODoH request to proxy `/proxy` with `X-ODoH-Blob` header
4. Proxy decrypts blob, cache miss → forwards ODoH body to target `/dns-query`
5. Target returns ODoH response + `X-Enclave-Cache` (HPKE-encrypted DNS response) + `X-Enclave-Cache-TTL`
6. Proxy decrypts cache entry with its private key, stores in LRU cache
7. Proxy returns ODoH response to client

**Flow (hit):**
1-3 same as above, but at step 4 proxy finds cache entry, encrypts with client's kc, returns `application/codoh-cached`

**Endpoints (Enclave-Proxy :10443):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/proxy` | POST | Main relay — decrypts blob, checks cache, forwards on miss |
| `/enclave-keys` | GET | Base64 HPKE public key |
| `/.well-known/odohconfigs` | GET | Proxied from target |
| `/health` | GET | Health check |

**Running manually:**

```bash
# 1. Start target
./coredns-test -conf benchmark/Corefile.codoh-base-target

# 2. Start enclave-proxy (simulation)
./enclave-sim -mode proxy -https-port 10443 \
    -tls-cert localhost.pem -tls-key localhost-key.pem \
    -target https://127.0.0.1:10444

# 3. Query via client
../codoh-client/odoh-client latency \
    --protocol codoh-base \
    --target 127.0.0.1:10444 \
    --proxy 127.0.0.1:10443 \
    --iterations 10 --domains benchmark/top-1m.csv \
    --distribution zipf \
    --customcert localhost.pem
```

**E2E test:** `./scripts/test-codoh-base-e2e.sh [--sgx]`

---

### Phase 1: VOPRF Token Issuance
- Target issues blind tokens via `/token` endpoint
- Tokens bound to epoch for rate limiting
- Client includes unblinded token in ODoH request

### Phase 2: Enclave Integration
- Proxy sends encrypted blob B to enclave via IPC
- Enclave verifies token, checks spent set, manages cache
- Cache hits return encrypted response without target roundtrip

### Phase 2f: SGX Attestation & Response Signing
- Enclave generates DCAP quote binding HPKE public key
- Target verifies quote and provisions master secret + signing pubkey via HTTPS
- Target signs DNS responses with Ed25519 before caching (binds response to query + blob B)
- Enclave verifies signatures on `store_encrypted` to prevent cache poisoning
- Simulation mode uses shared secret file for development

### Phase 3: Stochastic Cache Defenses (Snapshot Resistance)
Protects against memory snapshot attacks by making cache behavior unpredictable:

- **TTL-Aware Caching**: Target extracts DNS TTL and propagates via `X-Enclave-Cache-TTL` header
- **Hit Suppression (p_fn)**: Probabilistically return cache miss even when entry exists
- **Non-Insertion (p_ins)**: Probabilistically skip caching some responses
- **Random Churn** (ORAM only): Background eviction without user queries

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODOH_HIT_SUPPRESSION_PROB` | 0.0 | Probability of suppressing hits [0.0-1.0] |
| `CODOH_INSERT_PROB` | 1.0 | Probability of inserting entries [0.0-1.0] |
| `CODOH_CHURN_ENABLED` | false | Enable background churn (ORAM only) |
| `CODOH_CHURN_INTERVAL_SECS` | 0 | Seconds between churn events |
| `CODOH_USE_ORAM` | false | Use ORAM cache instead of LRU |
| `CODOH_ORAM_BLOCK_SIZE` | 4096 | ORAM block size in bytes |

#### Example Configurations

```bash
# Production (balanced)
CODOH_HIT_SUPPRESSION_PROB=0.1
CODOH_INSERT_PROB=0.9

# High Security (ORAM + churn)
CODOH_USE_ORAM=true
CODOH_HIT_SUPPRESSION_PROB=0.2
CODOH_INSERT_PROB=0.8
CODOH_CHURN_ENABLED=true
CODOH_CHURN_INTERVAL_SECS=60

# Maximum Security
CODOH_USE_ORAM=true
CODOH_HIT_SUPPRESSION_PROB=0.3
CODOH_INSERT_PROB=0.7
CODOH_CHURN_ENABLED=true
CODOH_CHURN_INTERVAL_SECS=30
```

#### Testing Stochastic Defenses

```bash
# Unit tests
cd enclave && go test -v -run "Test.*Suppression|Test.*Insertion|Test.*Churn"

# Benchmark different defense levels
./benchmark/run-stochastic-benchmark.sh --quick

# With ORAM cache
./benchmark/run-stochastic-benchmark.sh --quick --oram
```

---

## Benchmarking

Compare ODoH baseline vs CODoH (simulation and SGX) latency with real domain datasets.

### Quick Start

```bash
# Simulation only (ODoH baseline + CODoH simulation)
./benchmark/run-benchmark.sh 1000

# Include SGX hardware benchmark
./benchmark/run-benchmark.sh --sgx 1000
```

### What It Measures

| Benchmark | Description |
|-----------|-------------|
| ODoH (baseline) | Standard ODoH without tokens or enclave |
| CODoH Simulation (cold) | Sequential queries, empty cache |
| CODoH Simulation (zipf) | Zipf distribution, realistic cache behavior |
| CODoH Simulation (warm) | Single domain repeated, best-case cache |
| CODoH SGX (cold/zipf/warm) | Same as above with real SGX hardware |

### Output Files

Results saved to `benchmark/results/<timestamp>/`:

| File | Description |
|------|-------------|
| `odoh.csv/json` | ODoH baseline latencies |
| `codoh_sim_cold.csv/json` | CODoH simulation, cold cache |
| `codoh_sim_zipf.csv/json` | CODoH simulation, Zipf distribution |
| `codoh_sim_warm.csv/json` | CODoH simulation, warm cache |
| `codoh_sgx_*.csv/json` | CODoH SGX (only with `--sgx`) |

### Requirements

- `../codoh-client/odoh-client` built with latency command
- `localhost.pem` and `localhost-key.pem` in project root
- `dev-master-secret.txt` with 64 hex characters
- `benchmark/top-1m.csv` domain list

For SGX mode additionally:
- EGo SDK installed
- SGX device access (`sgx` and `sgx_prv` groups)
- PCCS configured

### Analyzing Results

```bash
# View summary
cat benchmark/results/<timestamp>/codoh_sim_zipf.json | jq '.mean, .p50, .p95, .p99'

# Compare all
cd benchmark/results/<timestamp>
for f in *.json; do echo "=== $f ==="; cat $f | grep -E '"(mean|p50|p95|cache_hit_rate)"'; done
```