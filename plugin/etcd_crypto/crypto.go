package etcd_crypto

import (
	"errors"
	"fmt"
)

// Type markers for encrypted records
const (
	TypeMarkerRSA     byte = 0x01 // RSA-PKCS1v15 encryption
	TypeMarkerWKDIBE  byte = 0x02 // WKD-IBE (akn07) encryption
	TypeMarkerCalypso byte = 0x03 // Calypso encryption
)

// detectAndDecrypt detects the encryption type marker and decrypts the value.
// If no type marker is found, the value is assumed to be plaintext JSON.
//
// Type markers:
//   - 0x01: RSA-PKCS1v15
//   - 0x02: WKD-IBE (akn07)
//   - 0x03: Calypso
//   - No marker: Plaintext JSON (passthrough)
//
// For Calypso decryption, etcdKey and pathPrefix are used to extract the concrete
// domain name for signature verification.
func detectAndDecrypt(value []byte, config *CryptoConfig, etcdKey string, pathPrefix string) ([]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("empty value")
	}

	// Check if first byte is a type marker
	switch value[0] {
	case TypeMarkerRSA:
		// RSA encrypted record - strip marker and decrypt
		if config == nil || config.RSAKey == nil {
			return nil, fmt.Errorf("RSA key not configured, cannot decrypt type 0x01 record")
		}
		return decryptRSA(value[1:], config.RSAKey)

	case TypeMarkerWKDIBE:
		// WKD-IBE encrypted record - strip marker and decrypt
		if config == nil || config.WKDIBEKey == nil {
			return nil, fmt.Errorf("WKD-IBE key not configured, cannot decrypt type 0x02 record")
		}
		return decryptWKDIBE(value[1:], config.WKDIBEKey)

	case TypeMarkerCalypso:
		// Calypso encrypted record - strip marker and decrypt
		if config == nil || config.CalypsoKey == nil {
			return nil, fmt.Errorf("Calypso key not configured, cannot decrypt type 0x03 record")
		}
		// Extract concrete domain from etcd key for signature verification
		domain, err := etcdKeyToDomain(etcdKey, pathPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to extract domain from etcd key: %w", err)
		}
		return decryptCalypso(value[1:], config.CalypsoKey, domain)

	default:
		// No recognized type marker - assume plaintext JSON
		// Plaintext records start with '{' (0x7B)
		return value, nil
	}
}