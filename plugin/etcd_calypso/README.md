# etcd_calypso

## Name

*etcd_calypso* - Zero Trust DNS plugin for Calypso encrypted records with search tag-based routing.

## Description

The *etcd_calypso* plugin implements **Zero Trust DNS** for Calypso encrypted records. CoreDNS performs **no decryption** - it only routes queries to search tag-based storage paths and returns encrypted data as-is to clients.

**Key Architecture:**
- **Zero Trust**: CoreDNS has no decryption keys, only performs SHA-256 hashing for path routing
- **Client-side decryption**: Encrypted TXT records are decrypted by authorized clients only
- **EDNS signaling**: Client sends EDNS option 65002 to trigger Calypso search tag routing
- **Reconnaissance prevention**: Records stored at `/skydns-calypso/[hash]` instead of hierarchical DNS paths

**How It Works:**
1. Client query includes EDNS option 65002 → CoreDNS detects Calypso request
2. CoreDNS computes search tag: `SHA256(domain pattern) → 64-char hex hash`
3. Lookup at `/skydns-calypso/[hash]` instead of `/skydns/com/example/domain`
4. Returns encrypted TXT record (marker `0x03`) to client without decryption
5. Client decrypts using Calypso reader key

For general etcd usage, configuration, and behavior, see the [etcd plugin README](../etcd/README.md).

## Syntax

```
etcd_calypso [ZONES...] {
    endpoint ENDPOINT...
    path PATH
    calypso_path_prefix PREFIX    # Optional: default is "skydns-calypso"
    calypso_max_depth DEPTH        # Optional: default is 5
}
```

**Directives:**

* `endpoint` - etcd endpoints (default: http://localhost:2379)
* `path` - base path in etcd (default: /skydns)
* `calypso_path_prefix` - prefix for Calypso hash-based storage (default: "skydns-calypso")
* `calypso_max_depth` - maximum domain depth for search tag computation (default: 5)

## Examples

**Basic configuration:**
```
.:1053 {
    etcd_calypso {
        endpoint http://localhost:2379
        path /skydns
    }
    log
}
```

**Custom Calypso settings:**
```
.:1053 {
    etcd_calypso {
        endpoint http://localhost:2379
        path /skydns
        calypso_path_prefix skydns-calypso
        calypso_max_depth 5
    }
    log
}
```

## Client Requirements

- DNS client must send EDNS option 65002 to signal Calypso handling
- Calypso reader key required for client-side decryption
- Example query: `CALYPSO_PARAMS_FILE=params.bin CALYPSO_KEY_FILE=reader.key ./q TXT verify.example.com @localhost:1053`

## Search Tag Computation

- Domain normalized: lowercase, trailing dot removed
- Pattern: reversed domain labels padded to maxDepth
- Concrete components joined with `\x00` separator
- Full SHA-256 hash (64 hex characters)

## See Also

[etcd plugin](../etcd/README.md) for complete etcd configuration details.