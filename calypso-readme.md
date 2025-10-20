# Development Notes for Calypso

## Overview

**EDNS Option Codes**:
- `65001` - JWT authentication token
- `65002` - WKDIBE encrypted record request
- `65003` - Calypso encrypted record request (includes searchtag payload)

**Encryption Type Markers** (in `TYPE:BASE64` format):
- `01:` - AES-256-GCM (server-side decryption in etcd_crypto)
- `02:` - WKDIBE (client-side decryption)
- `03:` - Calypso (client-side decryption)

---

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
7. **Configure Corefile** with required directives (see below)
8. **Start CoreDNS**: Run `./coredns`

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
  ./q A google.com @tls://localhost:8530 --jwt --token "<your-jwt-token>" --verbose
  ```

- **DNS over HTTPS**:
  ```shell
  ./q A google.com @https://localhost:443/dns-query --verbose
  ```

- **JWT-enforced DNS over HTTPS**:
  ```shell
  ./q A google.com @https://localhost:4430/dns-query --jwt --token "<your-jwt-token>" --verbose
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

The `etcd_calypso` plugin implements **Zero Trust DNS** with client-side encryption. CoreDNS performs **no decryption** - it only routes queries based on EDNS options and returns encrypted data as-is to authorized clients.

**Key Features**:
- **Zero Trust Architecture**: CoreDNS has no decryption keys
- **Three Request Types**:
  - Regular queries: Returns plaintext records, filters out encrypted ones
  - WKDIBE queries (EDNS 65002): Returns WKDIBE encrypted TXT records (marker `02:`)
  - Calypso queries (EDNS 65003): Returns Calypso encrypted TXT records (marker `03:`) using searchtag-based routing
- **Client-side decryption**: Only authorized clients with proper keys can decrypt responses
- **Reconnaissance prevention**: Calypso records stored at `/skydns-calypso/[searchtag]` instead of hierarchical DNS paths

**How It Works**:

*Regular DNS Query (no EDNS)*:
1. Client sends standard DNS query
2. CoreDNS looks up record at standard path `/skydns/com/example/domain`
3. Returns plaintext records, filters out any encrypted records (01:, 02:, 03:)

*WKDIBE Query (EDNS 65002)*:
1. Client includes EDNS option 65002
2. CoreDNS looks up at standard path `/skydns/com/example/domain`
3. Returns encrypted TXT record with `02:` prefix to client (no decryption)
4. Client decrypts using WKDIBE private key

*Calypso Query (EDNS 65003 with searchtag)*:
1. Client generates searchtag and includes it in EDNS option 65003
2. CoreDNS routes to `/skydns-calypso/[searchtag]`
3. Returns encrypted TXT record with `03:` prefix to client (no decryption)
4. Client decrypts using Calypso reader key

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
    }
    log
}
```

**Client Requirements**:

For WKDIBE queries:
- DNS client must send EDNS option 65002
- Example with `q` tool: `./q A --wkdibe --key=user.key domain.example.com @localhost:1053`
- WKDIBE private key for client-side decryption

For Calypso queries:
- DNS client must send EDNS option 65003 with searchtag payload
- Example with `q` tool: `./q A --calypso --params=params.bin --key=reader.key verify.example.com @localhost:1053`
- Calypso reader key for client-side decryption

**Testing with etcd-client**:

Register WKDIBE encrypted record:
```shell
cd /path/to/etcd-client
CRYPTO_TYPE=wkdibe \
WKDIBE_PARAMS_FILE=params.bin \
WKDIBE_MASTER_KEY=master.key \
./etcd-client -register wkdibe.example.com=10.0.0.5
```

Register Calypso encrypted record:
```shell
CRYPTO_TYPE=calypso \
CALYPSO_PARAMS_FILE=params.bin \
CALYPSO_WRITER_KEY=alice-writer.key \
./etcd-client -register verify.example.com=10.0.0.6
```

Query via CoreDNS:
```shell
# Regular query (returns only plaintext, filters encrypted)
./q A verify.example.com @localhost:1053

# WKDIBE query (returns encrypted record with 02: prefix)
./q A --wkdibe --key=user.key wkdibe.example.com @localhost:1053

# Calypso query (returns encrypted record with 03: prefix)
./q A --calypso --params=params.bin --key=alice-reader.key verify.example.com @localhost:1053
```


