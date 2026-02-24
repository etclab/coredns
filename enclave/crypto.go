package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	math_rand "math/rand"
	"sync"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// padRngPool provides per-goroutine math/rand PRNGs seeded from crypto/rand.
// Used for non-security-critical padding fill in PadToBucket and GenerateDummyResponse.
// The padding bytes are inside HPKE/AES-GCM ciphertext — only bucket size matters
// for G2/G3, not fill randomness. A sync.Pool eliminates mutex contention under
// concurrent enclave query processing.
var padRngPool = sync.Pool{
	New: func() any {
		var seed [8]byte
		crypto_rand.Read(seed[:])
		s := int64(binary.LittleEndian.Uint64(seed[:]))
		return math_rand.New(math_rand.NewSource(s))
	},
}

// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AES128GCM
	suite  = hpke.NewSuite(kemID, kdfID, aeadID)
	info = []byte("codoh transport key")

	// ExportLabel is the HPKE export label for deriving the response key k_r.
	ExportLabel = []byte("codoh response")
	// ExportKeyLen is the length of k_r in bytes (AES-128 key).
	ExportKeyLen uint = 16
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
	if _, err := crypto_rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, response, nil)

	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// DummyInnerSize is the representative size of an AES-128-GCM ciphertext
// used for dummy responses before PadToBucket. This produces a plausible
// 2-byte LE length prefix, making dummies structurally identical to real
// EncryptCachedResponse output after padding (C1 fix).
// Value: 12 (nonce) + 256 (median DNS response) + 16 (GCM tag) = 284.
const DummyInnerSize = 284

// GenerateDummyResponse returns size bytes of random data for dummy inner payloads
// that are subsequently wrapped with PadToBucket to match the structure of real
// encrypted responses. Uses math/rand (padding is inside ciphertext, not security-critical).
func GenerateDummyResponse(size int) []byte {
	buf := make([]byte, size)
	rng := padRngPool.Get().(*math_rand.Rand)
	rng.Read(buf)
	padRngPool.Put(rng)
	return buf
}

// DefaultPadBuckets is the default padding bucket set.
// A single bucket forces all responses (hits and misses) to exactly 16384 bytes,
// achieving complete size indistinguishability.
var DefaultPadBuckets = []int{16384}

// PadToBucket pads data to the next bucket boundary.
// Wire format: [2-byte LE length prefix][data][random padding]
// Total output length equals the smallest bucket >= len(data)+2.
// If data+2 exceeds the largest bucket, rounds up to the next multiple of the largest.
func PadToBucket(data []byte, buckets []int) ([]byte, error) {
	if len(buckets) == 0 {
		return nil, errors.New("empty bucket list")
	}

	needed := len(data) + 2 // 2-byte length prefix
	if needed > 65535+2 {
		return nil, errors.New("data too large for 2-byte length prefix")
	}

	// Find the smallest bucket that fits.
	// Caller MUST pass buckets in ascending sorted order.
	targetSize := 0
	for _, b := range buckets {
		if b >= needed {
			targetSize = b
			break
		}
	}

	// If no bucket fits, round up to next multiple of largest bucket
	if targetSize == 0 {
		largest := buckets[len(buckets)-1]
		targetSize = ((needed + largest - 1) / largest) * largest
	}

	out := make([]byte, targetSize)
	binary.LittleEndian.PutUint16(out[:2], uint16(len(data)))
	copy(out[2:], data)

	// Fill remaining bytes with fast PRNG padding (not security-critical — inside ciphertext)
	padStart := 2 + len(data)
	if padStart < targetSize {
		rng := padRngPool.Get().(*math_rand.Rand)
		rng.Read(out[padStart:])
		padRngPool.Put(rng)
	}

	return out, nil
}

// UnpadFromBucket extracts the original data from a padded message.
// Reads the 2-byte LE length prefix and returns the inner data.
func UnpadFromBucket(padded []byte) ([]byte, error) {
	if len(padded) < 2 {
		return nil, errors.New("padded data too short")
	}

	dataLen := int(binary.LittleEndian.Uint16(padded[:2]))
	if 2+dataLen > len(padded) {
		return nil, fmt.Errorf("invalid length prefix: %d exceeds padded size %d", dataLen, len(padded)-2)
	}

	return padded[2 : 2+dataLen], nil
}
