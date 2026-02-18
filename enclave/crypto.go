package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AES128GCM
	suite  = hpke.NewSuite(kemID, kdfID, aeadID)
	info = []byte("codoh-enclave-v2")

	// ExportLabel is the HPKE export label for deriving the response key k_r.
	ExportLabel = []byte("codoh response")
	// ExportKeyLen is the length of k_r in bytes (AES-128 key).
	ExportKeyLen uint = 16

	// DefaultPadSize is the default dummy response size in bytes.
	// Configurable via CODOH_DEFAULT_PAD_SIZE env var.
	DefaultPadSize = 512
)

// EnclaveKeypair holds the HPKE keypair for the enclave.
type EnclaveKeypair struct {
	PublicKey  kem.PublicKey
	PrivateKey kem.PrivateKey
}

// GenerateKeypair generates a new X25519 keypair for HPKE.
func GenerateKeypair() (*EnclaveKeypair, error) {
	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &EnclaveKeypair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// PublicKeyBytes returns the raw public key bytes (32 bytes for X25519).
func (k *EnclaveKeypair) PublicKeyBytes() ([]byte, error) {
	return k.PublicKey.MarshalBinary()
}

// Decrypt decrypts HPKE-encrypted data using the enclave's private key.
// Format: enc (32 bytes) || ciphertext
// Used for decrypting cache-insert blobs from target.
func (k *EnclaveKeypair) Decrypt(ciphertext []byte) ([]byte, error) {
	encSize := kemID.Scheme().CiphertextSize()
	if len(ciphertext) < encSize {
		return nil, errors.New("ciphertext too short for enc")
	}

	receiver, err := suite.NewReceiver(k.PrivateKey, info)
	if err != nil {
		return nil, fmt.Errorf("create receiver: %w", err)
	}

	enc := ciphertext[:encSize]
	ct := ciphertext[encSize:]

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("setup receiver: %w", err)
	}

	plaintext, err := opener.Open(ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptResponse encrypts a DNS response using a 32-byte symmetric key (kc).
// Used by proxy mode (CODoH-base, legacy v1 protocol).
// Format: nonce(12) || AES-128-GCM(kc[:16], nonce, response, nil)
func EncryptResponse(kc, response []byte) ([]byte, error) {
	if len(kc) < 16 {
		return nil, errors.New("kc must be at least 16 bytes")
	}

	block, err := aes.NewCipher(kc[:16])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	// Zero nonce for single-use kc (proxy mode only)
	nonce := make([]byte, gcm.NonceSize())
	ct := gcm.Seal(nil, nonce, response, nil)

	result := make([]byte, len(nonce)+len(ct))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// DecryptQueryE decrypts a client's Q_E using the enclave's private key and
// derives the session response key k_r via HPKE Export.
// Q_E format: enc(32 bytes) || ciphertext
// Returns the plaintext query and the 16-byte response key k_r.
func (k *EnclaveKeypair) DecryptQueryE(ciphertext []byte) (query []byte, kr []byte, err error) {
	encSize := kemID.Scheme().CiphertextSize()
	if len(ciphertext) < encSize+1 {
		return nil, nil, errors.New("Q_E too short")
	}

	receiver, err := suite.NewReceiver(k.PrivateKey, info)
	if err != nil {
		return nil, nil, fmt.Errorf("create receiver: %w", err)
	}

	enc := ciphertext[:encSize]
	ct := ciphertext[encSize:]

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, nil, fmt.Errorf("setup receiver: %w", err)
	}

	query, err = opener.Open(ct, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt Q_E: %w", err)
	}

	kr = opener.Export(ExportLabel, ExportKeyLen)
	return query, kr, nil
}

// EncryptCachedResponse encrypts a cached DNS response under k_r using AES-128-GCM.
// Returns: nonce(12) || ciphertext. Random nonce, no AAD.
func EncryptCachedResponse(kr, response []byte) ([]byte, error) {
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, response, nil)

	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// GenerateDummyResponse returns size bytes from crypto/rand.
// Indistinguishable from a real EncryptCachedResponse output.
func GenerateDummyResponse(size int) []byte {
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}
