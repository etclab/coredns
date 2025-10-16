# etcd_crypto

## Name

*etcd_crypto* - etcd plugin with AES-256-GCM encryption support

## Description

The *etcd_crypto* plugin extends the standard *etcd* plugin to support AES-256-GCM encrypted DNS records stored in etcd. Records are stored in a JSON wrapper format with type markers for consistent evaluation and comparison with other encryption schemes.

**Features:**
- AES-256-GCM authenticated encryption
- On-demand decryption during DNS query resolution
- JSON wrapper format with type marker (0x01)
- Backward compatible with plaintext records
- Consistent format for fair performance evaluation

For general etcd usage, configuration, and examples, see the [etcd plugin README](../etcd/README.md).

## Encryption Format

Encrypted records use a JSON wrapper format for consistency with other encryption schemes:

**Encrypted record:**
```json
{"text": "01:BASE64_CIPHERTEXT", "ttl": 300}
```

**Plaintext record:**
```json
{"host": "10.0.0.1", "ttl": 300}
```

Where:
- `01` = AES-256-GCM type marker (Approach 2: Enclave)
- `BASE64_CIPHERTEXT` = Base64-encoded [nonce (12 bytes)][AES-GCM ciphertext + auth tag (16 bytes)]

## Syntax

All standard `etcd` directives are supported, plus:

```
etcd_crypto [ZONES...] {
    # Standard etcd directives (see etcd plugin README)
    endpoint ENDPOINT...
    path PATH

    # AES key provisioning (optional)
    aes_key_file FILE
    aes_key_hex HEX_STRING
}
```

**Directives:**

* `aes_key_file` - Path to 32-byte binary AES-256 key file
* `aes_key_hex` - 64-character hex string representing 32-byte AES-256 key

**Notes:**
- If no AES key is configured, plugin operates in plaintext-only mode
- Paths can be absolute or relative to Corefile root
- Only one of `aes_key_file` or `aes_key_hex` can be specified
- Key must be exactly 32 bytes (256 bits)

## Examples

**AES with key file:**
```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        aes_key_file aes.key
    }
    log
}
```

**AES with hex key:**
```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
        aes_key_hex 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    }
    log
}
```

**Plaintext-only mode (no encryption):**
```
.:53 {
    etcd_crypto {
        endpoint http://localhost:2379
        path /skydns
    }
    log
}
```

## Key Generation

Generate a 32-byte AES key:

```bash
# Generate binary key file
openssl rand -out aes.key 32

# Or generate hex string
openssl rand -hex 32
```

## Encrypting DNS Records

Use the etcd-client tool to encrypt and store records:

```bash
# Generate AES key
openssl rand -out aes.key 32

# Register encrypted DNS record
CRYPTO_TYPE=aes AES_KEY_FILE=aes.key \
    etcd-client -register api.example.com=10.0.0.1

# Lookup encrypted record
CRYPTO_TYPE=aes AES_KEY_FILE=aes.key \
    etcd-client -lookup api.example.com

# List all records
etcd-client -list
```


## Storage Format Details

**Type Marker System:**
- `01` = AES-256-GCM encryption (Approach 2: Enclave)
- `02` = WKD-IBE encryption (Approach 3)
- `03` = Calypso encryption (Approach 4)
- No marker = Plaintext (Approach 0)

All encrypted schemes use the same JSON wrapper format `{"text": "TYPE:BASE64", "ttl": 300}` to enable fair performance comparison in research evaluations.

## See Also

[etcd plugin](../etcd/README.md) for complete etcd configuration details.