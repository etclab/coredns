# etcd_crypto

## Name

*etcd_crypto* - etcd plugin with support for encrypted DNS records

## Description

The *etcd_crypto* plugin extends the standard *etcd* plugin to support encrypted DNS records stored in etcd. It automatically detects and decrypts records encrypted with RSA, WKD-IBE, or Calypso while maintaining backward compatibility with plaintext records.

For general etcd usage, configuration, and examples, see the [etcd plugin README](../etcd/README.md).

## Encryption Support

Records are identified by a type marker prefix:
- `0x01` - RSA-PKCS1v15
- `0x02` - WKD-IBE (akn07)
- `0x03` - Calypso
- No marker - Plaintext (backward compatible)

## Syntax

All standard `etcd` directives are supported, plus:

```
etcd_crypto [ZONES...] {
    # Standard etcd directives (see etcd plugin README)
    endpoint ENDPOINT...
    path PATH

    # Encryption key files
    rsa_key_file FILE
    wkdibe_params_file FILE
    wkdibe_key_file FILE
    calypso_params_file FILE
    calypso_reader_key FILE
}
```

* `rsa_key_file` - Path to RSA private key (PEM format, PKCS#1 or PKCS#8)
* `wkdibe_params_file` - Path to WKD-IBE public parameters
* `wkdibe_key_file` - Path to WKD-IBE identity key
* `calypso_params_file` - Path to Calypso public parameters
* `calypso_reader_key` - Path to Calypso reader key

## Example

```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        rsa_key_file /etc/coredns/private.pem
    }
    log
}
```

## See Also

[etcd plugin](../etcd/README.md) for complete etcd configuration details.