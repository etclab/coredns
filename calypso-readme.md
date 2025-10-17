# Development Notes for Calypso

## Custom Plugins

### jwt_edns Plugin

The `jwt_edns` plugin enforces JWT authorization via EDNS OPT records (option code 65001). Clients must include valid JWT tokens in DNS queries to access protected DNS services.

**Setup Requirements**:
1. **Install tools**:
   - DNS query tool: `q` from https://github.com/etclab/q/tree/dev
   - JWT tools: `jwt-tools` from https://github.com/etclab/z-trustdns/tree/main for generating JWT tokens and public keys
2. **Register plugin**: Add `jwt_edns:jwt_edns` to `plugin.cfg` (below `log:log`)
3. **Build CoreDNS with custom plugin**:
   ```shell
   go generate
   go build .
   ```
4. **Generate certificates**: Run `./gen_certs.sh` to create TLS certificates for encrypted DNS transports
5. **Generate JWT key pair**:
   ```shell
   # Using jwt-tools
   ./jwt-tools generate-keys  # Creates private.pem and public.pem (EdDSA default)
   ```
6. **Generate JWT token**:
   ```shell
   ./jwt-tools generate-token --client-id "dns-client-1" --permissions "query" --allowed-zones "example.com" --expiry "30d"
   ```
7. **Start CoreDNS**: Run `./coredns` (key_file configured in Corefile)

**Corefile Configuration**:
```
# Standard DNS over UDP
.:1053 {
    forward . 1.1.1.1
    log
}

# DNS over TLS (DoT)
tls://.:853 {
    forward . tls://1.1.1.1
    tls cert.pem key.pem
    log
}

# DNS over TLS with JWT EDNS
tls://.:8530 {
    jwt_edns {
        algorithm eddsa
        key_file public.pem
    }
    forward . tls://1.1.1.1
    tls cert.pem key.pem
    log
}

# DNS over HTTPS (DoH)
https://.:443 {
    forward . 1.1.1.1
    tls cert.pem key.pem
    log
}

# DNS over HTTPS with JWT EDNS
https://.:4430 {
    jwt_edns {
        algorithm eddsa
        key_file public.pem
    }
    forward . 1.1.1.1
    tls cert.pem key.pem
    log
}
```

**Testing Examples**:

- **Plain DNS request**:
  ```shell
  ./q A google.com @localhost:1053 --verbose
  ```

- **Plain DNS over TLS**: Requires adding ca.pem to system store:
  ```shell
  # For Ubuntu/Debian based
  sudo cp ca.pem /usr/local/share/ca-certificates/ca.crt
  sudo update-ca-certificates
  # For MacOS
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
  ./q A google.com @tls://localhost:8530 --verbose
  ```

- **JWT-enforced DNS over TLS**:
  ```shell
  ./q A --jwt="<token>" --opt google.com @tls://localhost:8530 --verbose
  ```

- **DNS over HTTPS**:
  ```shell
  ./q A google.com @https://localhost:443/dns-query --verbose
  ```

- **JWT-enforced DNS over HTTPS**:
  ```shell
  ./q A google.com --jwt="<token>" --opt google.com @https://localhost:4430/dns-query --verbose
  ```

---

### etcd_crypto Plugin

The `etcd_crypto` plugin provides **AES-256-GCM encrypted DNS records** with server-side decryption. CoreDNS decrypts records on-demand during query resolution using a provisioned AES key.

**Key Features**:
- **AES-256-GCM**: Authenticated encryption (type marker `01`)
- **Server-side decryption**: CoreDNS has the key and decrypts before responding
- **JSON wrapper format**: Consistent `{"text": "01:BASE64", "ttl": 300}` structure
- **Backward compatible**: Supports plaintext records alongside encrypted ones

**Setup**:
1. **Register plugin**: Add `etcd_crypto:etcd_crypto` to `plugin.cfg` (after `etcd:etcd`)
2. **Build CoreDNS**:
   ```shell
   go generate
   go build .
   ```
3. **Generate AES key**: `openssl rand -out aes.key 32`

**Corefile Configuration**:
```
.:1053 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        aes_key_file aes.key
    }
    log
}
```

**Testing with etcd-client**:

Register encrypted record:
```shell
CRYPTO_TYPE=aes AES_KEY_FILE=aes.key \
./etcd-client -register api.example.com=10.0.0.1
```

Query (standard DNS - no special client requirements):
```shell
dig @localhost -p 1053 api.example.com
```

---

### etcd_calypso Plugin

The `etcd_calypso` plugin implements **Zero Trust DNS** for Calypso encrypted records. CoreDNS performs **no decryption** - it only routes queries to search tag-based storage paths and returns encrypted data as-is to clients.

**Key Architecture Principles**:
- **Zero Trust**: CoreDNS has no decryption keys, only performs SHA-256 hashing for path routing
- **Client-side decryption**: Encrypted TXT records are decrypted by authorized clients only
- **EDNS signaling**: Client sends EDNS option 65002 to trigger Calypso search tag routing
- **Reconnaissance prevention**: Records stored at `/skydns-calypso/[hash]` instead of hierarchical DNS paths

**How It Works**:
1. Client query includes EDNS option 65002 → CoreDNS detects Calypso request
2. CoreDNS computes search tag: `SHA256(domain pattern) → 64-char hex hash`
3. Lookup at `/skydns-calypso/[hash]` instead of `/skydns/com/example/domain`
4. Returns encrypted TXT record (marker `0x03`) to client without decryption
5. Client decrypts using Calypso reader key

**Setup**:
1. **Register plugin**: Add `etcd_calypso:etcd_calypso` to `plugin.cfg` (after `etcd:etcd`)
2. **Build CoreDNS**:
   ```shell
   go generate
   go build .
   ```

**Corefile Configuration**:
```
.:1053 {
    etcd_calypso {
        endpoint http://localhost:2379
        path /skydns
        calypso_path_prefix skydns-calypso  # Optional: default is "skydns-calypso"
        calypso_max_depth 5                 # Optional: default is 5
    }
    log
}
```

**Client Requirements**:
- DNS client must send EDNS option 65002 to signal Calypso handling
- Example with `q` tool: `CALYPSO_PARAMS_FILE=params.bin CALYPSO_KEY_FILE=reader.key ./q TXT verify.example.com @localhost:1053 `
- Calypso reader key for client-side decryption

**Testing with etcd-client**:

Register Calypso encrypted record:
```shell
cd /path/to/etcd-client
CRYPTO_TYPE=calypso \
CALYPSO_PARAMS_FILE=params.bin \
CALYPSO_WRITER_KEY=alice-writer.key \
./etcd-client -register verify.example.com=10.0.0.6
```

Query via CoreDNS (client with EDNS option 65002):
```shell
CALYPSO_PARAMS_FILE=params.bin CALYPSO_KEY_FILE=alice-reader.key ./q TXT verify.example.com @localhost:1053 --verbose
```

**Search Tag Computation** (matches etcd-client exactly):
- Domain normalized: lowercase, trailing dot removed
- Pattern: reversed domain labels padded to maxDepth
- Concrete components joined with `\x00` separator
- Full SHA-256 hash (64 hex characters)


