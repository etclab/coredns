# jwt_edns

## Name

*jwt_edns* - JWT authorization plugin for CoreDNS using EDNS (OPT Record)

## Description

The jwt_edns plugin enforces strict JWT authorization for DNS queries by extracting JWT tokens from EDNS OPT records. This plugin validates JWT tokens embedded in DNS requests using private EDNS option code 65001 and implements authenticated DNS resolution with zone-based access control.

**Security Model:**
- **Public key required at startup** - Plugin fails to initialize if `key_file` directive is not configured
- **All requests require JWT tokens** - No requests are allowed without valid JWT in EDNS option 65001
- **EDNS0 support mandatory** - Refuses requests without EDNS0 support
- **Asymmetric cryptography** - Supports RSA, ECDSA, and EdDSA signature algorithms

The plugin validates JWT tokens with custom claims including client identification, permissions, and optional zone restrictions. Invalid tokens or missing authorization return `dns.RcodeRefused`.

## Enforcements

The plugin applies the following enforcements in order (all violations result in `REFUSED` response):

### Hard Requirements
1. **EDNS0 Support** - Request must include EDNS0 extension
2. **JWT Token Presence** - JWT must be present in EDNS option code 65001
3. **Valid JWT Signature** - Token must verify with configured public key
4. **Signing Algorithm Match** - Token algorithm must match configured key type (RSA/ECDSA/EdDSA)
5. **Token Validity** - Standard JWT validation (expiration, not-before, etc.)

### Claims Validation
6. **`client_id` Required** - Must be present and non-empty
7. **`query` Permission Required** - Must be present in `permissions` array
8. **Zone Authorization** - If `allowed_zones` claim is specified, requested zone must match (supports suffix matching for subdomains)

### Example Rejection Scenarios
- No EDNS0 → `REFUSED`
- No JWT token in EDNS options → `REFUSED`
- Invalid/expired JWT signature → `REFUSED`
- Missing "query" permission → `REFUSED`
- Querying `evil.com` when `allowed_zones: ["example.com"]` → `REFUSED`
- Querying `sub.example.com` when `allowed_zones: ["example.com"]` → `ALLOWED` (suffix match)

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
jwt_edns {
    algorithm ALGORITHM
    key_file PATH
}
~~~

- **`algorithm`** - Optional. Signing algorithm: `rsa`, `ecdsa`, or `eddsa` (default: `eddsa`)
- **`key_file`** - Required. Path to PEM-encoded public key file for JWT validation

## Configuration

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

### Basic Configuration with EdDSA (default)

Enable JWT authorization via EDNS and forward queries to an upstream resolver:

~~~ corefile
. {
  jwt_edns {
    algorithm eddsa
    key_file /etc/coredns/public.pem
  }
  forward . 9.9.9.9
}
~~~

### With RSA Algorithm

~~~ corefile
. {
  jwt_edns {
    algorithm rsa
    key_file /etc/coredns/public.pem
  }
  log
  forward . 8.8.8.8
}
~~~

### Setup

1. **Generate key pair using jwt-tools**:
   ```bash
   # Navigate to jwt-tools directory
   cd ~/Projects/calypso/ztrust-dns/jwt-tools

   # Generate EdDSA key pair (default, recommended)
   ./jwt-tools generate-keys

   # Or generate with specific algorithm
   ./jwt-tools generate-keys --algorithm ES256  # ECDSA
   ./jwt-tools generate-keys --algorithm RS256  # RSA

   # This creates private.pem and public.pem
   ```

2. **Generate JWT token**:
   ```bash
   # Generate token for a client
   ./jwt-tools generate-token --client-id "dns-client-1" --permissions "query" --allowed-zones "example.com" --expiry "30d"

   # With specific algorithm
   ./jwt-tools generate-token --algorithm ES256 --client-id "client-1" --permissions "query" --expiry "30d"
   ```

3. **Configure Corefile** with the public key path in the `key_file` directive

4. **Start CoreDNS**:
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
