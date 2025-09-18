# jwt_edns

## Name

*jwt_edns* - JWT authorization plugin for CoreDNS using EDNS (OPT Record)

## Description

The jwt_edns plugin enforces JWT authorization for DNS queries by extracting JWT tokens from EDNS OPT records. This plugin validates JWT tokens embedded in DNS requests using private EDNS option code 65001 and can be used to implement authenticated DNS resolution.

The plugin parses incoming DNS requests for EDNS0 support, extracts JWT tokens from OPT record options, validates them using the `github.com/golang-jwt/jwt` library, and either allows the request to proceed to the next plugin or returns `dns.RcodeRefused` for invalid tokens.

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

In this configuration, we enable JWT authorization via EDNS and forward queries to an upstream resolver:

~~~ corefile
. {
  jwt_edns
  forward . 9.9.9.9
}
~~~

Or with additional logging:

~~~ corefile
. {
  jwt_edns
  log
  debug
}
~~~
Checking to see if EDNS0 is handled

  1. Test without EDNS0 (explicitly disable):
  ```console
  $dig @localhost +noedns example.com
  [DEBUG] plugin/jwt_edns: No EDNS0 support found, skipping JWT validation
  ```
  2. Test with EDNS0 (explicit enable):
  ```console
  $dig @localhost +edns=0 example.com
  [DEBUG] plugin/jwt_edns: EDNS0 support detected, checking for JWT token
  ```

## Also See

See the [manual](https://coredns.io/manual).
