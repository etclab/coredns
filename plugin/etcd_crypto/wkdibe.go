package etcd_crypto

import (
	"encoding/binary"
	"fmt"

	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/blspairing"
)

// WKDIBEKey holds WKD-IBE public parameters and private key for decryption
type WKDIBEKey struct {
	PublicParams *akn07.PublicParams
	PrivateKey   *akn07.PrivateKey
}

// Serialization helpers for WKD-IBE structures
func deserializeWKDIBEPublicParams(data []byte) (*akn07.PublicParams, error) {
	pp := &akn07.PublicParams{}
	if err := pp.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return pp, nil
}

func deserializeWKDIBEPrivateKey(data []byte) (*akn07.PrivateKey, error) {
	sk := &akn07.PrivateKey{}
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return sk, nil
}

// decryptWKDIBE decrypts a WKD-IBE encrypted record.
// The ciphertext format from etcd-client:
// [version(1)|IV_len(2)|IV(16)|AES_ct_len(4)|AES_ct(N)|WKDIBE_ct(M)]
func decryptWKDIBE(ciphertext []byte, wkdibeKey *WKDIBEKey) ([]byte, error) {
	if wkdibeKey == nil {
		return nil, fmt.Errorf("WKD-IBE key not configured")
	}
	if wkdibeKey.PublicParams == nil || wkdibeKey.PrivateKey == nil {
		return nil, fmt.Errorf("WKD-IBE public params or private key is nil")
	}

	// Minimum size check: version(1) + IV_len(2) + IV(16) + AES_ct_len(4) + at least some data
	if len(ciphertext) < 1+2+16+4+1 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	offset := 0

	// 1. Parse version
	version := ciphertext[offset]
	offset++
	if version != 1 {
		return nil, fmt.Errorf("unsupported ciphertext version: %d", version)
	}

	// 2. Parse IV length and IV
	ivLen := binary.BigEndian.Uint16(ciphertext[offset:])
	offset += 2
	if offset+int(ivLen) > len(ciphertext) {
		return nil, fmt.Errorf("invalid IV length: %d", ivLen)
	}
	iv := ciphertext[offset : offset+int(ivLen)]
	offset += int(ivLen)

	// 3. Parse AES ciphertext length and AES ciphertext
	if offset+4 > len(ciphertext) {
		return nil, fmt.Errorf("ciphertext too short for AES length")
	}
	aesCtLen := binary.BigEndian.Uint32(ciphertext[offset:])
	offset += 4
	if offset+int(aesCtLen) > len(ciphertext) {
		return nil, fmt.Errorf("invalid AES ciphertext length: %d", aesCtLen)
	}
	aesCt := ciphertext[offset : offset+int(aesCtLen)]
	offset += int(aesCtLen)

	// 4. Parse WKD-IBE ciphertext
	hibeCtBytes := ciphertext[offset:]
	hibeCt := &akn07.Ciphertext{}
	if err := hibeCt.UnmarshalBinary(hibeCtBytes); err != nil {
		return nil, fmt.Errorf("WKD-IBE ciphertext deserialization failed: %w", err)
	}

	// 5. WKD-IBE decrypt to get Gt element
	m := akn07.Decrypt(wkdibeKey.PublicParams, wkdibeKey.PrivateKey, hibeCt)

	// 6. Derive AES key from Gt
	aesKey := blspairing.KdfGtToAes256(m)

	// 7. AES-CTR decrypt
	plaintext, err := aesx.DecryptCTR(aesKey, iv, aesCt)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}