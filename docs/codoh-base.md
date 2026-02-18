# CODoH-base: Request Flow (Proxy Mode)

CODoH-base is the simplest CODoH variant. Two processes, no VOPRF tokens, no signatures, no IPC socket. The enclave runs as an HTTPS proxy that terminates the "simplified blob" and maintains a plaintext LRU cache.

## Architecture

```
                       HPKE blob (kc + query)
                       ODoH body (opaque)
Client  ──HTTPS──▶  Enclave-Proxy (:10443)  ──HTTPS──▶  CODoH Target (:10444)  ──UDP──▶  Upstream DNS
                     X25519 keypair                      ODoH keypair                    (8.8.8.8:53)
                     LRU cache
```

Two processes:

| Process | Binary | Port | Role |
|---------|--------|------|------|
| Enclave-Proxy | `enclave-sim` (or `enclave-sgx`) | 10443 | HPKE decrypt blob, cache lookup/store, forward to target |
| CODoH Target | `coredns-test` with `codohtarget` plugin | 10444 | ODoH decrypt/encrypt, upstream DNS resolution |

## Crypto Suite

Shared identically across enclave, target, and client:

```
KEM:   DHKEM(X25519, HKDF-SHA256)
KDF:   HKDF-SHA256
AEAD:  AES-128-GCM
Info:  "codoh-enclave-v1"
```

Two independent HPKE keypairs:

| Keypair | Owner | Purpose |
|---------|-------|---------|
| Enclave X25519 | Enclave-Proxy | Encrypt/decrypt the simplified blob and cache entries |
| ODoH HPKE | CODoH Target | Standard ODoH query/response encryption (RFC 9230) |

## HTTP Endpoints

### Enclave-Proxy (:10443)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/enclave-keys` | GET | Base64-encoded X25519 public key (text/plain) |
| `/proxy` | POST | Main handler: decrypt blob, check cache, forward |
| `/.well-known/odohconfigs` | GET | Proxied to target |
| `/health` | GET | Health check |

### CODoH Target (:10444)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/odohconfigs` | GET | ODoH HPKE config |
| `/dns-query` | POST | ODoH query handler |
| `/health` | GET | Health check |

## Content Types

| Content Type | Meaning |
|---|---|
| `application/oblivious-dns-message` | Standard ODoH message (cache miss response) |
| `application/codoh-cached` | Cache hit response encrypted under client's kc |

---

## Request Flow: Cache Miss

```
 Client                         Enclave-Proxy                    CODoH Target             Upstream
   │                                │                                │                       │
   │  1. GET /enclave-keys          │                                │                       │
   │  ─────────────────────────────▶│                                │                       │
   │  ◀─ enclave X25519 pubkey ─────│                                │                       │
   │                                │                                │                       │
   │  2. GET /.well-known/odohconfigs (proxied)                      │                       │
   │  ─────────────────────────────▶│───────────────────────────────▶│                       │
   │  ◀─ ODoH HPKE config ─────────│◀───────────────────────────────│                       │
   │                                │                                │                       │
   │  3. Build query:               │                                │                       │
   │     - ODoH-encrypt(dns_query)  │                                │                       │
   │     - kc = random 32 bytes     │                                │                       │
   │     - canon = "example.com.:1" │                                │                       │
   │     - blob = HPKE(kc ‖ canon)  │                                │                       │
   │                                │                                │                       │
   │  4. POST /proxy                │                                │                       │
   │     X-ODoH-Blob: base64(blob) │                                │                       │
   │     Body: ODoH query           │                                │                       │
   │  ─────────────────────────────▶│                                │                       │
   │                                │                                │                       │
   │                 5. Decrypt blob with enclave privkey             │                       │
   │                    Parse: kc (32B) + canonical query             │                       │
   │                    Cache.Get(query) → MISS                      │                       │
   │                                │                                │                       │
   │                                │  6. POST /dns-query            │                       │
   │                                │     Body: ODoH query           │                       │
   │                                │     X-Enclave-PubKey: base64   │                       │
   │                                │  ──────────────────────────────▶                       │
   │                                │                                │                       │
   │                                │               7. ODoH decrypt query                    │
   │                                │                  Resolve upstream ─────────────────────▶│
   │                                │                  ◀──── DNS response ───────────────────│
   │                                │                  ODoH encrypt response                  │
   │                                │                  HPKE encrypt(dns_resp) for enclave     │
   │                                │                                │                       │
   │                                │  ◀─────────────────────────────│                       │
   │                                │     Body: ODoH response        │                       │
   │                                │     X-Enclave-Cache: base64    │                       │
   │                                │     X-Enclave-Cache-TTL: secs  │                       │
   │                                │                                │                       │
   │                 8. Decrypt X-Enclave-Cache → plaintext DNS resp  │                       │
   │                    Cache.Put(query, resp, ttl)                   │                       │
   │                                │                                │                       │
   │  ◀─────────────────────────────│                                │                       │
   │     Content-Type: application/oblivious-dns-message             │                       │
   │     Body: ODoH response        │                                │                       │
   │                                │                                │                       │
   │  9. ODoH decrypt(response)     │                                │                       │
   │     → plaintext DNS answer     │                                │                       │
```

### Step by step

1. **Key fetch** — Client fetches the enclave's X25519 public key from `/enclave-keys` (cached 5 min client-side) and the target's ODoH config from `/.well-known/odohconfigs` (proxied through enclave).

2. **Client builds the request** — Two layers of encryption are prepared:
   - **ODoH layer**: Standard ODoH encryption of the DNS query under the target's HPKE key. Produces `odohQuery` + `queryContext` (kept for decrypting the response).
   - **Simplified blob**: `kc` (32 random bytes) concatenated with the canonicalized query (`"example.com.:1"`), then HPKE-encrypted to the enclave's public key.

3. **Client sends** — `POST /proxy` with the ODoH body and `X-ODoH-Blob` header.

4. **Enclave decrypts blob** — HPKE-decrypt extracts `kc` and the canonical query. Cache lookup with the query string: **miss**.

5. **Enclave forwards** — The ODoH body is forwarded verbatim to `POST /dns-query` on the target. The `X-Enclave-PubKey` header tells the target to encrypt a cache entry for the enclave.

6. **Target resolves** — Decrypts ODoH query, resolves via upstream DNS, encrypts the ODoH response. Additionally HPKE-encrypts the raw DNS response to the enclave's public key and attaches it as `X-Enclave-Cache` with `X-Enclave-Cache-TTL`.

7. **Enclave caches** — Decrypts `X-Enclave-Cache` with its private key, stores plaintext DNS response in the LRU cache keyed by the canonical query.

8. **Client decrypts** — Response has `Content-Type: application/oblivious-dns-message`. Client uses the ODoH `queryContext` to decrypt, yielding the DNS answer.

---

## Request Flow: Cache Hit

```
 Client                         Enclave-Proxy
   │                                │
   │  POST /proxy                   │
   │     X-ODoH-Blob: base64(blob) │
   │     Body: ODoH query           │
   │  ─────────────────────────────▶│
   │                                │
   │                 Decrypt blob → kc + canonical query
   │                 Cache.Get(query) → HIT (plaintext DNS resp)
   │                 AES-128-GCM encrypt(resp, key=kc[:16])
   │                                │
   │  ◀─────────────────────────────│
   │     Content-Type: application/codoh-cached
   │     Body: nonce(12B) ‖ ciphertext
   │                                │
   │  AES-128-GCM decrypt(body, kc[:16])
   │  → plaintext DNS answer        │
```

On a cache hit, the target is never contacted. The enclave encrypts the cached plaintext DNS response under the client's ephemeral `kc` (first 16 bytes as AES-128-GCM key) and returns it with `Content-Type: application/codoh-cached`.

The client distinguishes hit from miss by the response content type.

---

## Cache

CODoH-base uses a simple LRU cache inside the enclave (default 10,000 entries):

- **Key**: Canonicalized query string (e.g., `"example.com.:1"`)
- **Value**: Plaintext DNS response bytes
- **Eviction**: LRU + TTL-based expiry checked on Get
- **No stochastic defenses, no ORAM, no MLE** — those are used in the full CODoH (IPC mode) variants for snapshot resistance

## Security Properties

| Property | Status |
|----------|--------|
| Enclave cannot read ODoH query/response | Yes — ODoH payload passes through opaquely |
| Enclave sees the queried domain | Yes — the simplified blob contains the canonical query in plaintext (after HPKE decryption). This is the fundamental tradeoff enabling caching. |
| Target encrypts cache entries to enclave | Yes — via `X-Enclave-PubKey` / `X-Enclave-Cache` headers |
| Fresh kc per query | Yes — each query generates a new 32-byte random kc, so cache hit responses are encrypted differently for each client |
| No tokens or rate limiting | Correct — unlike full CODoH, no VOPRF tokens are used |