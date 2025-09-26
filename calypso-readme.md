# Development Notes for Calypso

## Custom jwt_edns Plugin

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
5. **Set public key environment variable**: The JWT signing algorithm requires its corresponding public key:
   - Keep public key in same folder: `export JWT_PUBLIC_KEY_PATH=public.pem`
   - Or specify custom path: `export JWT_PUBLIC_KEY_PATH=/path/to/your/public.pem`
6. **Start CoreDNS**: Run `./coredns` after setting the environment variable

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
    jwt_edns { algorithm eddsa }
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
    jwt_edns { algorithm eddsa }
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

