# CODoH Project Overview

## Goal

**CODoH (Cached Oblivious DNS over HTTPS)** extends ODoH (RFC 9230) with
privacy-preserving, proxy-side caching inside an SGX enclave. ODoH's per-query
ephemeral keys make a proxy cache useless — every query hits the target. CODoH
has the client encrypt each query to *both* the target and the enclave, so the
enclave serves cache hits directly, while ORAM, cover responses, and batched
insertions hide which entry was touched.

This document orients you to the implementation; see the paper for the full
design, security goals, and threat model.

---

## Security Goals

CODoH targets three properties (formal definitions in the paper):

- **G1 — Authorized & fresh answers:** a malicious proxy cannot make clients
  accept unauthorized or stale answers (no poisoning, tampering, replay).
- **G2 — Cache-state indistinguishability:** the proxy learns nothing by
  manipulating or comparing cache state over time (resists set-difference,
  priming, withholding, restart-reset).
- **G3 — Query-equality & profiling resistance:** the proxy cannot tell whether
  two requests are the same query, or profile clients from cache behavior.

The driving attack is **set-difference (bracketing)** — snapshot cache state,
admit one victim query, re-snapshot, diff to isolate the touched entry; the
G2/G3 defenses close it.

---

## Threat Model

A malicious proxy with full control of its position: the network-facing relay
(observe/delay/drop/replay/inject), request scheduling, the enclave's cache
lifecycle (restart-to-reset), and probing the cache as a client. Architectural
leakage (page-level access patterns, gross timing, message sizes) is in scope.
Out of scope: global traffic correlation, website fingerprinting,
microarchitectural TEE attacks (Spectre/Meltdown), and a malicious target or
proxy–target collusion. See the paper for the precise model.

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