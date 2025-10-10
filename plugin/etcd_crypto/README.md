# etcd_crypto

## Name

*etcd_crypto* - etcd plugin with support for encrypted DNS records

## Description

The *etcd_crypto* plugin extends the standard *etcd* plugin to support encrypted DNS records stored in etcd. It automatically detects and decrypts records encrypted with RSA, WKD-IBE, or Calypso while maintaining backward compatibility with plaintext records.

**Features:**
- On-demand decryption during DNS query resolution
- Type marker auto-detection (0x01=RSA, 0x02=WKD-IBE, 0x03=Calypso)
- Multi-scheme support (all three can coexist in same etcd instance)
- Plaintext passthrough for backward compatibility
- Calypso includes mandatory signature verification

For general etcd usage, configuration, and examples, see the [etcd plugin README](../etcd/README.md).

## Encryption Support

Records are identified by a type marker prefix:
- `0x01` - RSA-PKCS1v15 encryption
- `0x02` - WKD-IBE (akn07) hybrid encryption (IBE + AES-256-CTR)
- `0x03` - Calypso encryption with signature verification
- No marker - Plaintext (backward compatible)

## Syntax

All standard `etcd` directives are supported, plus:

```
etcd_crypto [ZONES...] {
    # Standard etcd directives (see etcd plugin README)
    endpoint ENDPOINT...
    path PATH

    # Encryption key files (mix and match as needed)
    rsa_key_file FILE
    wkdibe_params_file FILE
    wkdibe_key_file FILE
    calypso_params_file FILE
    calypso_key_file FILE
}
```

**Directives:**

* `rsa_key_file` - Path to RSA private key (PEM format, PKCS#1 or PKCS#8)
* `wkdibe_params_file` - Path to WKD-IBE public parameters (binary format)
* `wkdibe_key_file` - Path to WKD-IBE identity key (binary format)
* `calypso_params_file` - Path to Calypso public parameters (same as WKD-IBE params)
* `calypso_key_file` - Path to Calypso private key (writer or reader key, gob-encoded)

**Notes:**
- All paths can be absolute or relative to Corefile root
- WKD-IBE requires both `wkdibe_params_file` and `wkdibe_key_file` together
- Calypso requires both `calypso_params_file` and `calypso_key_file` together
- Multiple schemes can be configured simultaneously

## Examples

**RSA-only configuration:**
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

**WKD-IBE-only configuration:**
```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        wkdibe_params_file /etc/coredns/params.bin
        wkdibe_key_file /etc/coredns/alice.key
    }
    log
}
```

**Calypso-only configuration:**
```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        calypso_params_file /etc/coredns/params.bin
        calypso_key_file /etc/coredns/alice-writer.key
    }
    log
}
```

**Multi-scheme configuration (all three):**
```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        rsa_key_file /etc/coredns/private.pem
        wkdibe_params_file /etc/coredns/params.bin
        wkdibe_key_file /etc/coredns/alice.key
        calypso_params_file /etc/coredns/params.bin
        calypso_key_file /etc/coredns/alice-writer.key
    }
    log
}
```

## Key Generation

Keys must be generated using compatible tools:

- **RSA**: Standard OpenSSL (`openssl genrsa -out private.pem 2048`)
- **WKD-IBE**: Use etcd-client `wkdibe setup` and `wkdibe keygen` commands
- **Calypso**: Use etcd-client `calypso setup` and `calypso keygen` commands

See etcd-client documentation for WKD-IBE and Calypso key generation.

## Security Notes

- **RSA**: No signature verification - sender authentication relies on key secrecy
- **WKD-IBE**: Identity-based encryption - keys derived from domain patterns
- **Calypso**: Domain-specific signature verification with search tags - prevents reconnaissance and enumeration of registered domains
- Calypso writer keys can decrypt + sign; reader keys can only decrypt
- Search tags hide domain names from etcd observers - must know specific domain to decrypt

## See Also

[etcd plugin](../etcd/README.md) for complete etcd configuration details.