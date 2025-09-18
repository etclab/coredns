# jwt_edns

## Name

*jwt_edns* - JWT authorization plugin for CoreDNS using EDNS (OPT Record)

## Description

The jwt_edns plugin enforces strict JWT authorization for DNS queries by extracting JWT tokens from EDNS OPT records. This plugin validates JWT tokens embedded in DNS requests using private EDNS option code 65001 and implements authenticated DNS resolution with zone-based access control.

**Security Model:**
- **Public key required at startup** - Plugin fails to initialize if `JWT_PUBLIC_KEY_PATH` environment variable is not set
- **All requests require JWT tokens** - No requests are allowed without valid JWT in EDNS option 65001
- **EDNS0 support mandatory** - Refuses requests without EDNS0 support
- **Asymmetric cryptography** - Supports RSA, ECDSA, and EdDSA signature algorithms

The plugin validates JWT tokens with custom claims including client identification, permissions, and optional zone restrictions. Invalid tokens or missing authorization return `dns.RcodeRefused`.

## Compilation

This package will always be compiled as part of CoreDNS and not in a standalone way. It will require you to use `go get` or as a dependency on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg).

The [manual](https://coredns.io/manual/toc/#what-is-coredns) will have more information about how to configure and extend the server with external plugins.

A simple way to consume this plugin, is by adding the following on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg), and recompile it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
jwt_edns:jwt_edns
~~~

Put this early in the plugin list, so that *jwt_edns* is executed before any of the other plugins to ensure proper authorization.

After this you can compile coredns by:

``` sh
go generate
go build
```

Or you can instead use make:

``` sh
make
```

## Syntax

~~~ txt
jwt_edns
~~~

## Configuration

### Environment Variables

- `JWT_PUBLIC_KEY_PATH` - **Required**. Path to PEM-encoded public key file for JWT validation.

### JWT Claims Structure

The plugin expects JWT tokens with the following custom claims:

```json
{
  "client_id": "unique-client-identifier",
  "permissions": ["query"],
  "allowed_zones": ["example.org", "test.com"],
  "iss": "jwt-issuer",
  "sub": "subject",
  "iat": 1234567890,
  "exp": 1234567890,
  "nbf": 1234567890
}
```

**Required Claims:**
- `client_id` - Unique client identifier
- `permissions` - Must include "query" permission
- Standard JWT claims (`iss`, `sub`, `iat`, `exp`, `nbf`)

**Optional Claims:**
- `allowed_zones` - If specified, restricts DNS queries to listed zones

### Supported Algorithms

- **RSA**: RS256, RS384, RS512
- **ECDSA**: ES256, ES384, ES512
- **EdDSA**: Ed25519 (default)

## Dependencies

This plugin requires the following dependency:
- `github.com/golang-jwt/jwt/v5` for JWT parsing and validation

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metric is exported:

* `coredns_jwt_edns_request_count_total{server}` - query count to the *jwt_edns* plugin.

The `server` label indicated which server handled the request, see the *metrics* plugin for details.

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

### Basic Configuration

Enable JWT authorization via EDNS and forward queries to an upstream resolver:

~~~ corefile
. {
  jwt_edns
  forward . 9.9.9.9
}
~~~

### With Logging

~~~ corefile
. {
  jwt_edns
  log
  forward . 8.8.8.8
}
~~~

### Setup

1. **Generate key pair**:
   ```bash

   # ECDSA key pair (recommended for smaller tokens):
   openssl ecparam -genkey -name prime256v1 -noout -out private.pem
   openssl ec -in private.pem -pubout -out public.pem

   # Generate private key
   openssl genrsa -out private.pem 2048

   # Extract public key
   openssl rsa -in private.pem -pubout -out public.pem
   ```

2. **Set environment variable**:
   ```bash
   export JWT_PUBLIC_KEY_PATH=/path/to/public.pem
   ```

3. **Start CoreDNS**:
   ```bash
   ./coredns -conf Corefile
   ```

### Testing Behavior

With the strict security model, all requests are refused unless they contain valid JWT tokens:

```bash
# Request without EDNS0 - REFUSED
dig @localhost +noedns example.com

# Request with EDNS0 but no JWT token - REFUSED
dig @localhost +edns=0 example.com

# Request with valid JWT token in EDNS option 65001 - ALLOWED
# (requires custom DNS client that can embed JWT in EDNS options)
```


## Also See

See the [manual](https://coredns.io/manual).
