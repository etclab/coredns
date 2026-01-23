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
| `/tokens` | POST | VOPRF token issuance |
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
| IPC: `store` | Store response in cache |
| IPC: `ready` | Check if enclave is provisioned |
| HTTPS: `/attest` | Get SGX quote + public key |
| HTTPS: `/provision` | Receive encrypted master secret |
| HTTPS: `/health` | Health check |

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
   "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/"
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
| `rate_limit` | Tokens per IP per epoch | 100 |
| `master_secret` | Path to 32-byte hex secret | required |
| `enclave_url` | Enclave HTTPS URL (SGX mode) | - |
| `enclave_mrsigner` | Expected MRSIGNER (SGX mode) | - |

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
| `enclave_bypass_on_failure` | Continue without enclave if unavailable | false |

---

## What's Implemented

### Phase 1: VOPRF Token Issuance
- Target issues blind tokens via `/tokens` endpoint
- Tokens bound to epoch for rate limiting
- Client includes unblinded token in ODoH request

### Phase 2: Enclave Integration
- Proxy sends encrypted blob B to enclave via IPC
- Enclave verifies token, checks spent set, manages cache
- Cache hits return encrypted response without target roundtrip

### Phase 2f: SGX Attestation
- Enclave generates DCAP quote binding HPKE public key
- Target verifies quote and provisions master secret via HTTPS
- Simulation mode uses shared secret file for development