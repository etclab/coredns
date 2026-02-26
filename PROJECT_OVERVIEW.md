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
| **Client** | codoh-client/ | Go CLI | Query originator, Q_E + Q_T encryption, query padding |
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
   |  Q_E = Pad(HPKE.Seal(pk_E, query))      |                    |
   |  Q_T = Pad(ODoH envelope)              |                    |
   |  (both padded to 512B bucket)          |                    |
   |                   |                     |                    |
   |-- Q_T + Q_E ----->|                     |                    |
   |  (X-CoDOH-Query)  |                     |                    |
   |                   |== parallel fan-out ==|                    |
   |                   |-- process(Q_E) ---->|                    |
   |                   |                     | Unpad + Decrypt Q_E|
   |                   |                     | Derive k_r (Export)|
   |                   |                     | Check cache        |
   |                   |                     |                    |
   |                   |-- Q_T + pk_E ------>|----> Target ------>|
   |                   |  (X-Enclave-PubKey) |                    |
   |                   |                     |                    |
   |                   |<-- HIT: Enc(k_r, resp) [or dummy on MISS]|
   |                   |                     |                    |
   |                   |<-- ODoH response ---|                    |
   |                   |                     |                    |
   |                   |                     | (async) POST /cache-insert
   |                   |                     | with real + k covers
   |                   |<--- cache-insert ---|--------------------+
   |                   |                     |                    |
   |                   |-- store_encrypted ->| Verify Ed25519 sig |
   |                   |  (per entry in batch)| Validate timestamp |
   |                   |                     | Decrypt bundle     |
   |                   |                     | Enqueue for batch  |
   |                   |                     |                    |
   |<-- response ------|                     |                    |
   |  (tagged chunks: enclave + target)      |                    |
```

**Key properties:**
- Q_E and Q_T are padded to a fixed 512-byte bucket before transmission (G3: all queries are identical size on the wire)
- Proxy fans out Q_E to enclave and Q_T to target in parallel
- On cache miss, enclave returns a dummy response indistinguishable from a hit (same size)
- Proxy streams both results as tagged chunks (`application/codoh-response`): `[1B type][2B BE len][data]...` — whichever leg (enclave or target) finishes first is flushed immediately
- Chunk types: `ChunkTypeEnclave=1` (cache hit or dummy), `ChunkTypeTarget=2` (ODoH response)
- Client parses both chunks; uses enclave chunk on hit, target chunk on miss
- If enclave errors, proxy degrades to plain ODoH (`application/oblivious-dns-message`)
- Response key `k_r` is derived via HPKE Export from the Q_E context — implicitly bound to the ephemeral KEM key
- **Config 3 (proxy mode)** uses `application/codoh-cached` (single response, no tagged chunks)

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
| IPC server (Unix socket) | enclave/ipc.go | Binary wire protocol: [4B len][1B type/status][payload] |
| LRU cache with logical-time TTL | enclave/cache.go | container/list, sync.RWMutex |
| ORAM cache (Path ORAM) | enclave/oram_cache.go | FNV hash mapping, lazy expiry |
| Cache interface | enclave/cache_interface.go | Get/Put/Size/Clear/CleanExpired |
| Cache-insert bundle format | enclave/bundle.go | ttl + timestamp + query + response; also CanonicalizeQuery |
| Ed25519 signature verification | enclave/cmd/main.go | On cache-insert bundles |
| Timestamp replay protection | enclave/cmd/main.go | Monotonic t_latest + δ-window |
| Dummy response generation | enclave/crypto.go | crypto/rand, same size as real |
| Query-path padding (Q_E unpad) | enclave/cmd/main.go | UnpadFromBucket before DecryptQueryE |
| Query canonicalization | enclave/bundle.go | domain:qtype format (CanonicalizeQuery) |
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
| Batched cache updates | enclave/insertion_queue.go, enclave/cmd/main.go | Bounded FIFO queue, signal-coalescing batchWorker goroutine, PutBatch on Cache interface |
| | | |
| **Proxy Plugin** | | |
| Parallel fan-out (enclave + target) | plugin/codohproxy/proxy.go | Concurrent goroutines |
| Tagged chunk streaming | plugin/codohproxy/proxy.go | `application/codoh-response`: [1B type][2B len][data] per chunk |
| /enclave-keys endpoint | plugin/codohproxy/proxy.go | Serves pk_E (cached in-memory) |
| /proxy endpoint | plugin/codohproxy/proxy.go | Main CODoH relay |
| Enclave IPC client | plugin/codohproxy/enclave_client.go | Unix socket client, connection pool (cap 4) |
| Key rotation header forwarding | plugin/codohproxy/proxy.go | Sets X-CoDOH-Key-Rotated header on key_rotated status |
| Bypass mode | plugin/codohproxy/proxy.go | Falls back to plain ODoH |
| Prometheus metrics | plugin/codohproxy/metrics.go | |
| Config options | plugin/codohproxy/setup.go | Corefile parsing |
| | | |
| **Target Plugin** | | |
| ODoH DNS resolution | plugin/codohtarget/target.go | /dns-query endpoint (unpads Q_T before processing) |
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
| Cover responses | G2 | Done | Target samples k random domains (codohtarget/cover/), delivered via POST /cache-insert |
| Batched cache insertions | G2 | Done | InsertionQueue + pseudorandom commit via crypto/rand coin flip on query path |
| Wire-layer padding (responses) | G2, G3 | Done | Bucketed padding (default single 16384-byte bucket); hits and misses identical size to proxy |
| Wire-layer padding (queries) | G3 | Done | Q_E and Q_T padded to fixed 512-byte bucket; all queries identical size to proxy/network observer |
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
| CODOH_PAD_BUCKETS | "16384" | Comma-separated padding bucket sizes (bytes) |
| CODOH_REPLAY_DELTA_SECS | 3.0 | Timestamp replay window (seconds) |
| CODOH_TARGET_SIGNING_PUBKEY | - | Base64 Ed25519 pubkey (sim mode only) |
| CODOH_WARMUP_THRESHOLD | 100 | Cache entries needed to exit defensive mode |
| CODOH_OMISSION_THRESHOLD | 50 | Outstanding queries to trigger defensive mode |
| CODOH_OUTSTANDING_TTL_SECS | 300 | Logical-time window (seconds) for outstanding query eviction |
| CODOH_BATCH_SIZE | 10 | Entries per batch commit |
| CODOH_BATCH_COMMIT_PROB | 0.1 | Probability of batch commit per HandleProcess call |
| CODOH_QUEUE_MAX_SIZE | 1000 | Max pending inserts in the insertion queue |

### Target Environment Variables (Cover Responses)

| Variable | Default | Description |
|----------|---------|-------------|
| CODOH_COVER_COUNT | 3 | Cover domains per cache-insert (0 to disable) |
| CODOH_COVER_DOMAIN_FILE | - | Path to domain list CSV (required when COVER_COUNT > 0) |
| CODOH_COVER_POPULAR_CUTOFF | 10000 | Top-N domains treated as "popular" in sampler |
| CODOH_COVER_POPULAR_RATIO | 0.8 | Fraction of covers drawn from popular tier |
| CODOH_COVER_RESOLVER | 127.0.0.1:53 | DNS resolver for cover domain resolution |
| CODOH_COVER_TIMEOUT_MS | 2000 | Timeout for cover DNS resolution (ms) |
| CODOH_PROXY_CALLBACK_URL | - | Proxy base URL for cache-insert delivery (required) |

---

## HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| X-CoDOH-Query | Client -> Proxy | Base64-encoded Q_E (HPKE-encrypted query) |
| X-Enclave-PubKey | Proxy -> Target | Base64-encoded enclave HPKE public key |
| X-CoDOH-Key-Rotated | Proxy -> Client | `true` when enclave pk_E has rotated; client should re-fetch from `/enclave-keys` |
| X-CoDOH-Enclave-Error | Proxy -> Client | Error code when enclave leg fails (e.g., `key_rotated`, `enclave_unavailable`) |

**Note:** Cache-insert bundles are no longer delivered via HTTP headers. The target POSTs a JSON payload to the proxy's `/cache-insert` endpoint asynchronously (including k cover entries).

## Content Types

| Content-Type | Description |
|--------------|-------------|
| application/oblivious-dns-message | Standard ODoH (RFC 9230); also used as degraded fallback when enclave fails |
| application/codoh-response | IPC mode (Configs 4, 5): tagged chunks `[1B type][2B BE len][data]...` containing enclave + target responses |
| application/codoh-cached | Proxy mode only (Config 3): cached response from enclave (AES-GCM under k_r) |

---

## IPC Protocol (Unix Socket)

```
Wire format: [4 bytes: total length (big-endian)][1 byte: type/status][payload]

All payloads are binary (no JSON).

Request types (1-byte opcodes):
  0x01 = process          (payload: padded HPKE ciphertext; enclave unpads before decrypt)
  0x02 = store_encrypted  (payload: [4B blob_len][blob][signature])
  0x03 = get_pubkey       (no payload)
  0x04 = health           (no payload)

Response status (1-byte codes):
  0x00 = ok
  0x01 = processed        (payload: encrypted response or dummy)
  0x02 = error            (payload: error code string)
  0x03 = key_rotated      (no payload)

Error codes: invalid_blob, decrypt_failed, hpke_error,
             invalid_signature, stale_timestamp, internal_error

Max message size: 64 KiB (maxIPCMessageSize)
```

**Note:** Hit vs miss is NOT distinguished at the IPC layer. The enclave always returns `processed` (0x01) with either a real encrypted response or a same-size dummy. In IPC mode, the proxy streams both chunks to the client via `application/codoh-response`; the client determines hit vs miss by attempting decryption of the enclave chunk with `k_r`.

---

## Operating Modes

### IPC Mode (Configs 4, 5) — 3-process architecture

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
│   ├── bundle.go              # CacheInsertBundle marshal/parse + CanonicalizeQuery
│   ├── ipc.go                 # Unix socket server (binary wire protocol)
│   ├── cache.go               # LRU cache with logical-time TTL
│   ├── cache_interface.go     # Cache interface (Get/Put/PutBatch/Size/Clear/CleanExpired)
│   ├── oram_cache.go          # Path ORAM cache (access-pattern hiding)
│   ├── insertion_queue.go     # Bounded FIFO queue for batched cache inserts
│   ├── config.go              # Configuration loading (env vars)
│   ├── types.go               # IPC message types
│   ├── attestation.go         # HTTPS attestation server (/attest, /provision)
│   ├── attestation_sgx.go     # SGX-specific: quote generation, attested TLS
│   ├── attestation_sim.go     # Simulation fallbacks
│   ├── enclave.json           # EGo manifest (dev, CODOH_* fromHost)
│   ├── enclave-prod.json      # EGo manifest (prod, no env passthrough)
│   └── Makefile               # Build targets (build, sign, run, sim, dev)
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
│       ├── cover/             # Cover response generation
│       │   ├── sampler.go     # Tiered domain sampling (popular/long-tail)
│       │   └── resolver.go    # DNS resolution for cover domains
│       ├── setup.go           # Corefile parsing
│       └── metrics.go         # Prometheus metrics
│
├── benchmark/                  # Benchmarking tools
│   ├── configs/               # Config profiles (sourceable, 5 files)
│   │   ├── 1-doh.sh           # DoH baseline
│   │   ├── 2-odoh.sh          # ODoH baseline
│   │   ├── 3-codoh-base.sh    # CODoH-base (2-proc proxy mode, worktree)
│   │   ├── 4-codoh-nosgx.sh   # CODoH-nosgx (3-proc IPC, full defenses, no SGX)
│   │   └── 5-codoh-full.sh    # CODoH-full (3-proc IPC, full defense stack, SGX)
│   ├── setup.sh               # Shared setup/teardown helpers
│   ├── run-all.sh             # Multi-config orchestrator
│   └── top-1m.csv             # Domain list (+ subsets: top-10, top-1k, etc.)
│
└── codoh-client/              # Client (separate repo)
    └── commands/
        ├── blob.go            # Q_E encryption (HPKE), PadToBucket/UnpadFromBucket
        ├── commands.go        # CLI flags (--protocol codoh)
        ├── enclave_state.go   # pk_E caching + refresh on key rotation
        ├── request.go         # HTTP request construction
        └── latency.go         # Latency benchmarking
```

---

## Testing

### Automated Tests (SGX)

All scripts require SGX hardware and EGo SDK.

```bash
./scripts/test-stack-simple.sh         # Quick Config 5 smoke test (build + 3 processes + client)
./scripts/test-attestation-e2e.sh      # Full attestation flow (quote, provisioning, queries)
./scripts/test-codoh-base-e2e.sh       # Config 3 proxy mode (2-process)
./scripts/test-provisioning.sh         # Focused provisioning test (enclave + target only)
```

### Benchmarking

```bash
./benchmark/run-all.sh                 # All configs
./benchmark/run-all.sh --quick         # 100 iterations, cold only
./benchmark/run-all.sh --configs 1,3,4,5
```

### Manual Testing (SGX, Config 5)

Launch order matters: enclave must serve `/attest` before target starts.

```bash
# Terminal 1: Build + start enclave (SGX)
cd enclave && ego-go build -tags ego -o enclave ./cmd && ego sign enclave.json && cd ..
go build -o coredns-test .
CODOH_CACHE_SIZE=10000 CODOH_BATCH_SIZE=10 CODOH_BATCH_COMMIT_PROB=1.0 \
CODOH_WARMUP_THRESHOLD=5 CODOH_REPLAY_DELTA_SECS=30 \
ego run enclave/enclave --socket /tmp/codoh-enclave.sock

# Terminal 2: Start target (provisions signing key via attestation)
CODOH_COVER_COUNT=3 CODOH_COVER_DOMAIN_FILE=benchmark/top-1m.csv \
CODOH_PROXY_CALLBACK_URL=https://127.0.0.1:8080 \
CODOH_COVER_RESOLVER=8.8.8.8:53 CODOH_COVER_TIMEOUT_MS=2000 \
./coredns-test -conf Corefile.target

# Terminal 3: Start proxy
./coredns-test -conf Corefile.proxy

# Terminal 4: Test
../codoh-client/odoh-client latency --protocol codoh \
  --target 127.0.0.1:8443 --proxy 127.0.0.1:8080 \
  --customcert localhost.pem \
  --domains benchmark/top-1m.csv --iterations 10
```

### SGX Build Nuances

- `ego-go` does **not** auto-set the `ego` build tag — always pass `-tags ego`
- `go.mod` must use `go 1.25.1` for ego-go compatibility (ego ships Go 1.25.1)
- `enclave/enclave.json` must list all `CODOH_*` env vars with `"fromHost": true`
- `ego-host` child processes don't die when `ego run` parent is killed — clean up by port