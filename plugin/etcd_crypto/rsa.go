package etcd_crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// decryptRSA decrypts RSA-PKCS1v15 encrypted data using the provided private key.
// The ciphertext should NOT include the type marker byte.
func decryptRSA(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("RSA private key is nil")
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}

	fmt.Printf("[DEBUG RSA] Ciphertext length: %d bytes, key size: %d bits\n", len(ciphertext), privateKey.N.BitLen())

	// Decrypt using RSA-PKCS1v15 (keeping inline with etcd-client; could update to OAEP later)
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		fmt.Printf("[ERROR RSA] Decryption failed: %v\n", err)
		return nil, fmt.Errorf("RSA decryption failed: %w", err)
	}

	fmt.Printf("[DEBUG RSA] Decryption succeeded, plaintext length: %d bytes\n", len(plaintext))
	return plaintext, nil
}