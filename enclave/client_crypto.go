package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

// EncryptQueryE encrypts a query to the enclave's public key using HPKE.
// Returns Q_E ciphertext (enc || ct) and the session response key k_r.
// k_r = senderCtx.Export("codoh response", 16)
func EncryptQueryE(pkE kem.PublicKey, query []byte) (qe []byte, kr []byte, err error) {
	sender, err := suite.NewSender(pkE, info)
	if err != nil {
		return nil, nil, fmt.Errorf("create sender: %w", err)
	}

	enc, sealer, err := sender.Setup(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("setup sender: %w", err)
	}

	ct, err := sealer.Seal(query, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("seal query: %w", err)
	}

	kr = sealer.Export(ExportLabel, ExportKeyLen)

	qe = make([]byte, len(enc)+len(ct))
	copy(qe, enc)
	copy(qe[len(enc):], ct)

	return qe, kr, nil
}

// DecryptCachedResponse decrypts an enclave's cached response under k_r.
// Expected format: nonce(12) || AES-128-GCM ciphertext.
// Returns plaintext DNS response or error (AEAD auth failure = cache miss/dummy).
func DecryptCachedResponse(kr, blob []byte) ([]byte, error) {
	if len(kr) < 16 {
		return nil, errors.New("kr must be at least 16 bytes")
	}

	block, err := aes.NewCipher(kr[:16])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize+gcm.Overhead() {
		return nil, errors.New("blob too short")
	}

	nonce := blob[:nonceSize]
	ct := blob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD open: %w", err)
	}

	return plaintext, nil
}

// ParsePublicKeyBytes deserializes a raw X25519 public key (32 bytes).
func ParsePublicKeyBytes(raw []byte) (kem.PublicKey, error) {
	pk, err := kemID.Scheme().UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %w", err)
	}
	return pk, nil
}
