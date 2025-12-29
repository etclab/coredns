# ODoH CoreDNS Plugins

Two plugins implementing RFC 9230 (Oblivious DNS over HTTPS):

- **odohtarget**: Decrypts queries, resolves upstream, encrypts responses
- **odohproxy**: Stateless relay between client and target

## Generate TLS Certs

```bash
brew install mkcert
mkcert -install
mkcert -key-file localhost-key.pem -cert-file localhost.pem localhost 127.0.0.1
```

## Build

```bash
go generate && go build
```

## Test Setup

### Target Corefile (`target-corefile`)
```
. {
    odohtarget {
        port 8443
        tls_cert localhost.pem
        tls_key localhost-key.pem
        upstream 8.8.8.8:53
    }
}
```

### Proxy Corefile (`proxy-corefile`)
```
. {
    odohproxy {
        target https://127.0.0.1:8443/dns-query
        port 8080
        tls_cert localhost.pem
        tls_key localhost-key.pem
        insecure_skip_verify true
    }
}
```

## Running

```bash
# Terminal 1: Target
./coredns -conf target-corefile

# Terminal 2: Proxy
./coredns -conf proxy-corefile
```

## Testing with odoh-client-go

```bash
# Fetch target config
./odoh-client odohconfig-fetch --target 127.0.0.1:8443 --pretty

# Full ODoH query via proxy
./odoh-client odoh --domain example.com. --dnstype A \
  --target 127.0.0.1:8443 \
  --proxy 127.0.0.1:8080
```

## Endpoints

**Target (8443)**
- `GET /.well-known/odohconfigs` - HPKE public key
- `POST /dns-query` - ODoH query endpoint
- `GET /health` - Health check

**Proxy (8080)**
- `POST /proxy?targethost=...&targetpath=...` - Relay endpoint
- `GET /health` - Health check