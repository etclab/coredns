# CODoH CoreDNS Plugins

Implementation of Cached Oblivious DNS over HTTPS (CODoH), extending RFC 9230 ODoH with:
- SGX enclave for secure response caching and HPKE decryption
- Remote attestation for secure signing-key provisioning
- ORAM cache option for access-pattern hiding

## Architecture

```
Client ──► Proxy ──► Target ──► Upstream DNS
              │
              ▼
           Enclave (SGX)
           - HPKE decryption
           - Response caching
           - Cache-insert verification
```

## Plugins

- **codohtarget**: ODoH target with cache-insert encryption and Ed25519 signing
- **codohproxy**: ODoH proxy with enclave IPC integration for caching
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
go build -o enclave-sim ./enclave/cmd

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

### 1. Start Enclave (Simulation)

```bash
./enclave-sim --socket /tmp/codoh-enclave.sock
```

### 2. Start Target

Using `Corefile.target`:
```
.:5354 {
    codohtarget {
        port 8443
        tls_cert localhost.pem
        tls_key localhost-key.pem
        upstream 8.8.8.8:53
        signing_key /tmp/target-signing.pem
        log_queries true
    }
}
```

```bash
./coredns -conf Corefile.target
```

### 3. Start Proxy

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

### 4. Test with odoh-client

```bash
cd ../codoh-client

# CODoH latency test (IPC mode)
./odoh-client latency \
    --protocol codoh \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert ../coredns/localhost.pem \
    --domains ../coredns/benchmark/top-1m.csv \
    --iterations 10
```

---

## Endpoints

### Target (default :8443)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/odohconfigs` | GET | HPKE public key config |
| `/dns-query` | POST | ODoH query endpoint |
| `/health` | GET | Health check |

### Proxy (default :8080)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/proxy` | POST | CODoH relay endpoint |
| `/enclave-keys` | GET | Enclave HPKE public key |
| `/health` | GET | Health check |

### Enclave (IPC + HTTPS in SGX mode)

| Endpoint | Description |
|----------|-------------|
| IPC: `process` | Decrypt Q_E, check cache, return encrypted response or dummy |
| IPC: `store_encrypted` | Enqueue HPKE-encrypted response for batched cache commit |
| IPC: `get_pubkey` | Get enclave's HPKE public key |
| IPC: `health` | Health check (`started_at`, `queue_depth`, `total_commits`, `total_entries_committed`) |
| HTTPS: `/attest` | Get SGX quote + public key |
| HTTPS: `/provision` | Receive signing pubkey for cache-insert verification |
| HTTPS: `/health` | Health check |

---

## HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-CoDOH-Query` | Client -> Proxy | Base64-encoded Q_E (HPKE-encrypted query) |
| `X-Enclave-PubKey` | Proxy -> Target | Base64-encoded enclave HPKE public key |
| `X-Enclave-Cache` | Target -> Proxy | Base64-encoded HPKE-encrypted cache-insert bundle |
| `X-Enclave-Cache-Sig` | Target -> Proxy | Base64-encoded Ed25519 signature |
| `X-Enclave-Cache-TTL` | Target -> Proxy | TTL in seconds for cache entry |
| `X-CoDOH-Key-Rotated` | Proxy -> Client | `true` when enclave pk_E has rotated (restart). Client should re-fetch pk_E from `/enclave-keys` |
| `X-CoDOH-Enclave-Error` | Proxy -> Client | Error code when enclave leg fails (e.g., `key_rotated`, `enclave_unavailable`) |

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
    //\"pccs_url\": \"https://api.trustedservices.intel.com/sgx/certification/v4/\"
    \"pccs_url\": \"https://localhost:8081/sgx/certification/v4/\"
    // To accept insecure HTTPS certificate, set this option to false
    ,\"use_secure_cert\": false
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
    signing_key /path/to/signing-key.pem
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

### Enclave Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODOH_CACHE_SIZE` | 10000 | Number of cache entries |
| `CODOH_USE_ORAM` | false | Use ORAM cache instead of LRU |
| `CODOH_ORAM_BLOCK_SIZE` | 4096 | ORAM block size in bytes |
| `CODOH_DEFAULT_PAD_SIZE` | 512 | Dummy response size in bytes |
| `CODOH_TARGET_SIGNING_PUBKEY` | - | Base64 Ed25519 pubkey (simulation mode only) |
| `CODOH_WARMUP_THRESHOLD` | 100 | Cache entries needed to exit defensive mode |
| `CODOH_OMISSION_THRESHOLD` | 50 | Outstanding queries to trigger defensive mode |
| `CODOH_OUTSTANDING_TTL_SECS` | 300 | Logical-time window (seconds) for outstanding query eviction |
| `CODOH_BATCH_SIZE` | 10 | Entries per batch commit |
| `CODOH_BATCH_COMMIT_PROB` | 0.1 | Probability of batch commit per HandleProcess call |
| `CODOH_QUEUE_MAX_SIZE` | 1000 | Max pending inserts in the insertion queue |

---

## What's Implemented

### CODoH IPC Mode (Configs 4-7)

Full 3-process architecture with enclave-based caching, HPKE encryption, and Ed25519 signature verification.

```
Client → Proxy (codohproxy plugin) → Target (codohtarget plugin) → Upstream DNS
            │
            ▼
         Enclave (IPC over Unix socket)
```

**Processes:**

1. **Enclave** (`enclave-sim` or SGX `enclave`) — HPKE keypair, cache (LRU or ORAM), Q_E decryption, cache-insert verification, batched cache updates, defensive mode, omission detection
2. **Proxy** (`codohproxy` plugin, port 8080) — fans out Q_E to enclave + Q_T to target in parallel
3. **Target** (`codohtarget` plugin, port 8443) — ODoH resolution, cache-insert bundle construction, Ed25519 signing

**Flow (miss):**
1. Client fetches enclave public key from proxy `/enclave-keys`
2. Client encrypts Q_E (query under enclave's HPKE public key)
3. Client sends ODoH request to proxy `/proxy` with `X-CoDOH-Query` header
4. Proxy fans out: sends Q_E to enclave (IPC) and Q_T to target (HTTPS) in parallel
5. Enclave decrypts Q_E, cache miss → returns dummy (indistinguishable from hit)
6. Target resolves DNS, builds cache-insert bundle, encrypts under enclave pubkey, signs with Ed25519
7. Proxy fires async `store_encrypted` IPC to enclave with encrypted bundle + signature. Enclave enqueues entry for batched commit.
8. Proxy returns ODoH response to client

**Flow (hit):**
1-4 same as above, but enclave finds cached response, encrypts under session key k_r (derived via HPKE Export), returns `status: "hit"`
5. Proxy returns two-chunk response: enclave's encrypted cached response + target's ODoH response
6. Client decrypts cached response with k_r

**Defensive Mode (Sprint 3):**

The enclave starts in defensive mode on boot and enters it again if it detects cache omission attacks. In defensive mode, all queries return `status:"miss"` with a dummy blob — indistinguishable from a normal cache miss to the proxy.

- **Boot warm-up**: `defensiveMode=true` on start. Exits when `cache.Size() >= WarmupThreshold` (default 100).
- **Omission detection**: Tracks outstanding queries (misses without corresponding stores). When `len(outstandingQueries) > OmissionThreshold` (default 50), enters defensive mode, clears cache, clears outstanding map. Recovery is the same: fill cache to threshold.
- **Outstanding TTL**: Entries older than `OutstandingTTLSecs` (default 300s, logical time) are evicted inline during `store_encrypted` handling.
- **Key rotation**: HPKE decryption failure returns `status:"key_rotated"`. Proxy sets `X-CoDOH-Key-Rotated: true` header. Client re-fetches pk_E from `/enclave-keys`.
- **Health**: Returns `started_at` (RFC3339) for restart detection, plus `queue_depth`, `total_commits`, and `total_entries_committed` batch stats.

**Batched Cache Updates (Sprint 4):**

Cache inserts are not applied immediately. `HandleStoreEncrypted` enqueues entries into a bounded FIFO (`InsertionQueue`). Batch commits fire probabilistically at the end of each `HandleProcess` call via a `crypto/rand` coin flip.

- **Commit trigger**: Only on the query path (`HandleProcess`), never on the store path. Prevents the proxy from controlling commit timing (G2).
- **Queue overflow**: Head-drop (oldest evicted). No force-commit on overflow — keeps commits on the pseudorandom schedule.
- **Omission detection**: Outstanding queries are removed on enqueue (not on commit), so batching delay does not cause false omission detection.
- **Warm-up interaction**: Cache fills via batch commits, so warm-up exit is delayed by batching latency. At defaults (~100 QPS), the queue is in equilibrium.
- **Defaults**: `BatchSize=10`, `BatchCommitProb=0.1`, `QueueMaxSize=1000`. At 100 QPS this yields ~100 entries/sec committed with a steady-state queue depth of ~100.
- **Testing tip**: Set `CODOH_BATCH_COMMIT_PROB=1.0` for deterministic commit behavior in manual tests.

**IPC Response Statuses:**
| Status | Meaning |
|--------|---------|
| `hit` | Cache hit, encrypted response under k_r |
| `miss` | Cache miss (or defensive mode), dummy blob |
| `ok` | Successful store or health check |
| `error` | Operation failed (see `error` field) |
| `key_rotated` | HPKE decryption failed, client has stale pk_E |

### CODoH-base (Proxy Mode, Config 3)

Minimal 2-process architecture. A single HTTPS proxy handles HPKE decryption and LRU caching directly — no separate enclave process, no IPC, no signatures. In SGX deployment, this proxy would run inside an enclave via EGo.

```
Client → Proxy (HTTPS, built-in cache) → ODoH Target → Upstream DNS
```

**Processes:**

1. **ODoH Target** (`codohtarget` plugin, port 10444)
2. **Proxy** (`enclave-sim -mode proxy`, port 10443) — HTTPS server with HPKE keypair and LRU cache

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

---

## Client pk_E Management

The client caches the enclave public key (pk_E) via `EnclaveState` (in `codoh-client/commands/enclave_state.go`):

- **One `EnclaveState` per command invocation** (benchmark loop, latency test, single query)
- `GetOrFetchPubKey()` returns the cached key; fetches from `/enclave-keys` on first call
- `RefreshPubKey()` forces a network re-fetch — called when `X-CoDOH-Key-Rotated: true` is received
- Fetches directly from `/enclave-keys`, bypassing the global TTL cache in `FetchEnclavePublicKey()`

---

## Benchmarking

Compare protocol configurations with the multi-config orchestrator.

### Quick Start

```bash
# Run all configs (1-5,7)
./benchmark/run-all.sh

# Quick mode (100 iterations, cold only)
./benchmark/run-all.sh --quick

# Specific configs
./benchmark/run-all.sh --configs 1,3,4,5

# SGX mode
./benchmark/run-all.sh --sgx
```

### Configurations

| Config | Name | Protocol | Architecture |
|--------|------|----------|--------------|
| 1 | DoH baseline | DoH | Direct |
| 2 | ODoH baseline | ODoH | 2-process (proxy + target) |
| 3 | CODoH-base | CODoH | 2-process (enclave-proxy + target) |
| 4 | CODoH token | CODoH | 3-process IPC (enclave + proxy + target) |
| 5 | CODoH ORAM | CODoH | 3-process IPC with ORAM cache |
| 7 | CODoH full | CODoH | 3-process IPC with ORAM cache |

### Output Files

Results saved to `benchmark/results/<timestamp>/`:

| File | Description |
|------|-------------|
| `<config>_cold.csv/json` | Sequential queries, empty cache |
| `<config>_zipf.csv/json` | Zipf distribution, realistic cache behavior |
| `<config>_warm.csv/json` | Single domain repeated, best-case cache |
| `comparison.png` | Gnuplot comparison chart |

### Requirements

- `../codoh-client/odoh-client` built
- `localhost.pem` and `localhost-key.pem` in project root
- `benchmark/top-1m.csv` domain list (and optionally `top-1k.csv`)
