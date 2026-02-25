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
# IMPORTANT: ego-go does NOT auto-set the 'ego' build tag — must pass -tags ego
# IMPORTANT: go.mod must use go 1.25.1 for ego-go compatibility (ego ships Go 1.25.1)
cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave.json
```

**enclave.json**: Must list all `CODOH_*` env vars with `"fromHost": true` or they won't be visible inside the enclave. See `enclave/enclave.json` for the current list.

---

## Automated Testing

All scripts require SGX hardware and EGo SDK.

```bash
./scripts/test-stack-simple.sh         # Quick Config 4 smoke test (build + run + client)
./scripts/test-attestation-e2e.sh      # Full attestation flow (quote, provisioning, queries)
./scripts/test-codoh-base-e2e.sh       # Config 3 proxy mode (2-process)
./scripts/test-provisioning.sh         # Focused provisioning test (enclave + target only)
```

---

## Manual Testing

Launch order: **enclave → target → proxy**. In SGX mode, the enclave blocks on provisioning until the target calls `/attest` + `/provision`.

### 1. Start Enclave (SGX)

```bash
cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave.json && cd ..

CODOH_CACHE_SIZE=10000 CODOH_BATCH_SIZE=10 CODOH_BATCH_COMMIT_PROB=1.0 \
CODOH_WARMUP_THRESHOLD=5 CODOH_REPLAY_DELTA_SECS=30 \
ego run enclave/enclave --socket /tmp/codoh-enclave.sock
```

Wait for "Attestation server listening on https://0.0.0.0:8444" before starting the target.

### 2. Start Target

`Corefile.target` must include `enclave_url` for SGX attestation-based provisioning:
```
.:5353 {
    codohtarget {
        port 8443
        tls_cert localhost.pem
        tls_key localhost-key.pem
        upstream 8.8.8.8:53
        signing_key /tmp/target-signing.pem
        enclave_url https://127.0.0.1:8444
        log_queries true
    }
}
```

```bash
CODOH_COVER_COUNT=3 \
CODOH_COVER_DOMAIN_FILE=benchmark/top-1m.csv \
CODOH_PROXY_CALLBACK_URL=https://127.0.0.1:8080 \
CODOH_COVER_RESOLVER=8.8.8.8:53 \
CODOH_COVER_TIMEOUT_MS=2000 \
./coredns-test -conf Corefile.target
```

Without `CODOH_PROXY_CALLBACK_URL`, cache-insert delivery is silently disabled.

### 3. Start Proxy

```bash
./coredns-test -conf Corefile.proxy
```

The proxy auto-registers `POST /cache-insert` when `enclave_enabled` is set.

### 4. Test with odoh-client

```bash
../codoh-client/odoh-client latency \
    --protocol codoh \
    --target 127.0.0.1:8443 \
    --proxy 127.0.0.1:8080 \
    --customcert localhost.pem \
    --domains benchmark/top-1m.csv \
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
| `/cache-insert` | POST | Receives cache-insert bundles from target (when `enclave_enabled`) |
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
| `X-CoDOH-Key-Rotated` | Proxy -> Client | `true` when enclave pk_E has rotated (restart). Client should re-fetch pk_E from `/enclave-keys` |
| `X-CoDOH-Enclave-Error` | Proxy -> Client | Error code when enclave leg fails (e.g., `key_rotated`, `enclave_unavailable`) |

**Note:** Cache-insert bundles are delivered via `POST /cache-insert` (JSON payload with real entry + k covers), not via HTTP headers.

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
ego-go build -tags ego -o enclave ./cmd   # -tags ego is REQUIRED (not auto-set)
ego sign enclave.json
ego run enclave --socket /tmp/codoh-enclave.sock --https-port 8444
```

**Cleanup note:** `ego-host` child processes don't die when `ego run` parent is killed. Clean up by port: `lsof -ti :8444 | xargs kill`

### Target with Enclave Provisioning

```
codohtarget {
    ...
    signing_key /path/to/signing-key.pem
    enclave_url https://localhost:8444        # triggers attestation flow
    enclave_mrsigner <64 hex chars>           # optional, from: ego signerid enclave
}
```

For quote verification on the target side, build with `-tags sgxverify` (requires Open Enclave SDK). Without it, verification is skipped with a warning.

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

| Variable | Type | Default | Paper Symbol | Description |
|----------|------|---------|-------------|-------------|
| `CODOH_CACHE_SIZE` | int | 10000 | N | Max cache entries |
| `CODOH_USE_ORAM` | bool | false | — | ORAM-backed cache (required for G2) |
| `CODOH_ORAM_BLOCK_SIZE` | int | 4096 | — | ORAM block size (bytes) |
| `CODOH_PAD_BUCKETS` | string | "16384" | — | Comma-separated padding bucket sizes (bytes) |
| `CODOH_REPLAY_DELTA_SECS` | float | 3.0 | δ | Replay protection window (seconds) |
| `CODOH_WARMUP_THRESHOLD` | int | 100 | — | Cache entries needed to exit defensive mode |
| `CODOH_OMISSION_THRESHOLD` | int | 50 | — | Outstanding queries to trigger defensive mode |
| `CODOH_OUTSTANDING_TTL_SECS` | int | 300 | — | Logical-time window (seconds) for outstanding query eviction |
| `CODOH_BATCH_SIZE` | int | 10 | B | Entries per batch commit |
| `CODOH_BATCH_COMMIT_PROB` | float | 0.1 | p | Per-query commit probability |
| `CODOH_QUEUE_MAX_SIZE` | int | 1000 | — | Max pending inserts in insertion queue |
| `CODOH_TARGET_SIGNING_PUBKEY` | string | — | — | Base64 Ed25519 pubkey (simulation mode only) |

### Target Environment Variables (Cover Responses)

| Variable | Type | Default | Paper Symbol | Description |
|----------|------|---------|-------------|-------------|
| `CODOH_COVER_COUNT` | int | 3 | k | Cover responses per cache-insert (0 to disable) |
| `CODOH_COVER_DOMAIN_FILE` | path | — | — | Domain list CSV (required when COVER_COUNT > 0) |
| `CODOH_COVER_POPULAR_CUTOFF` | int | 10000 | — | Top-N domains treated as "popular" in sampler |
| `CODOH_COVER_POPULAR_RATIO` | float | 0.8 | — | Fraction of covers drawn from popular tier |
| `CODOH_COVER_RESOLVER` | string | 127.0.0.1:53 | — | DNS resolver for cover domain resolution |
| `CODOH_COVER_TIMEOUT_MS` | int | 2000 | — | Timeout for cover DNS resolution (ms) |
| `CODOH_PROXY_CALLBACK_URL` | URL | — | — | Proxy base URL for `POST /cache-insert` delivery |

---

## What's Implemented

### CODoH IPC Mode (Config 4)

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
3. **Target** (`codohtarget` plugin, port 8443) — ODoH resolution, cache-insert bundle construction, Ed25519 signing, cover response generation

**Flow (miss):**
1. Client fetches enclave public key from proxy `/enclave-keys`
2. Client encrypts Q_E (query under enclave's HPKE public key)
3. Client sends ODoH request to proxy `/proxy` with `X-CoDOH-Query` header
4. Proxy fans out: sends Q_E to enclave (IPC) and Q_T to target (HTTPS) in parallel
5. Enclave decrypts Q_E, cache miss → returns dummy (indistinguishable from hit)
6. Target resolves DNS, builds cache-insert bundle (real + k covers), encrypts each under enclave pubkey, signs with Ed25519
7. Target asynchronously POSTs bundle batch to proxy's `/cache-insert` endpoint
8. Proxy fires `store_encrypted` IPC to enclave for each entry. Enclave enqueues for batched commit.
9. Proxy returns ODoH response to client

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
2. **Proxy** (`ego run enclave -mode proxy`, port 10443) — HTTPS server with HPKE keypair and LRU cache

**Running manually:**

```bash
# 1. Start target
./coredns-test -conf benchmark/Corefile.codoh-base-target

# 2. Start enclave-proxy (SGX)
ego run enclave/enclave -mode proxy -https-port 10443 \
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
# Run all configs (1-4)
./benchmark/run-all.sh

# Quick mode (100 iterations, cold only)
./benchmark/run-all.sh --quick

# Specific configs
./benchmark/run-all.sh --configs 1,3,4,5

# Simulation mode (SGX is the default)
./benchmark/run-all.sh --no-sgx
```

### Configurations

| Config | Name | Protocol | Architecture |
|--------|------|----------|--------------|
| 1 | DoH baseline | DoH | Direct |
| 2 | ODoH baseline | ODoH | 2-process (proxy + target) |
| 3 | CODoH-base | CODoH | 2-process (enclave-proxy + target) |
| 4 | CODoH-full | CODoH | 3-process IPC with full defense stack |

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

### Cloud Benchmarks (Multi-VM)

Multi-VM setup for measuring realistic cross-network latency. Three VMs: **Proxy** (SGX enclave + codohproxy), **Target** (codohtarget + resolver), **Client** (odoh-client).

```
Client VM ──HTTPS──▶ Proxy VM (SGX) ──HTTPS──▶ Target VM
 odoh-client          enclave + proxy            codohtarget + resolver
                      (Unix socket)
```

**Setup (one-shot from client VM):**

```bash
# 1. Configure IPs
cp benchmark/cloud-env.sh benchmark/cloud-env.local.sh
# Edit cloud-env.local.sh: set PROXY_IP, TARGET_IP

# 2. Provision all VMs (run from client VM only)
# Clones repos, installs Go/EGo, builds binaries on proxy + target via SSH
./benchmark/cloud-provision.sh

# Or provision each VM manually (run ON the VM)
./benchmark/cloud-setup.sh proxy    # on DCsv3 (SGX) VM
./benchmark/cloud-setup.sh target   # on target VM
./benchmark/cloud-setup.sh client   # on client VM
```

**Prerequisites:** SSH key auth to proxy/target, `gh auth login` on all VMs (with HTTPS protocol: `gh config set git_protocol https`).

**Running (from client VM):**

```bash
./benchmark/cloud-run.sh --quick                # smoke test (configs 2,3,4, 50q)
./benchmark/cloud-run.sh --standard             # comparison (configs 2,3,4, 10Kq)
./benchmark/cloud-run.sh --configs 2,3,4 --iterations 5000
./benchmark/cloud-run.sh --no-sgx               # simulation mode
```

**Options:**

| Flag | Description |
|------|-------------|
| `--configs 2,3,4` | Run specific configs only |
| `--quick` | 50 queries, warm workload, configs 2,3,4 |
| `--standard` | 10K queries, all workloads, configs 2,3,4 |
| `--no-sgx` | Use enclave-sim instead of SGX |
| `--resolver cloudflare` | Upstream resolver (cloudflare/google/HOST:PORT) |
| `--run-id NAME` | Name for results directory |

**Port/VM Matrix:**

| Port | Process | VM | Configs |
|------|---------|-----|---------|
| 8080 | codohproxy | Proxy | 4 |
| 8444 | enclave attestation | Proxy | 4 |
| 9080 | odohproxy | Proxy | 2 |
| 10443 | enclave-proxy (config 3) | Proxy | 3 |
| 7443 | DoH server | Target | 1 |
| 8443 | codohtarget | Target | 4-7 |
| 9443 | odohtarget | Target | 2 |
| 10444 | codoh-base-target | Target | 3 |

**Collecting Logs:**

```bash
./benchmark/cloud-collect-logs.sh <run-id>
```

**Files:**

| File | Purpose |
|------|---------|
| `benchmark/cloud-env.sh` | Template env (copy to `cloud-env.local.sh`) |
| `benchmark/cloud-provision.sh` | One-shot bootstrapper (clones repos + provisions all VMs from client) |
| `benchmark/cloud-setup.sh` | Per-VM provisioner (`proxy\|target\|client`) |
| `benchmark/cloud-run.sh` | Cross-VM orchestrator (runs from client VM) |
| `benchmark/cloud-collect-logs.sh` | Post-run log fetcher |

Local single-machine benchmarks still work unchanged via `./benchmark/run-all.sh` — config IP vars default to `127.0.0.1`.
