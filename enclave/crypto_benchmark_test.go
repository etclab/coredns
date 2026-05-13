package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// Representative payload sizes matching real workloads (see microbenchmarks.tex).
const (
	benchQuerySize    = 193  // max padded Q_E
	benchResponseSize = 512  // median DNS response
)

func BenchmarkHPKE_Seal(b *testing.B) {
	kp, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	query := make([]byte, benchQuerySize)
	rand.Read(query)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := EncryptQueryE(kp.PublicKey, query)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHPKE_Open(b *testing.B) {
	kp, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	query := make([]byte, benchQuerySize)
	rand.Read(query)

	// Pre-encrypt to get ciphertexts for decryption
	ciphertexts := make([][]byte, b.N)
	for i := range ciphertexts {
		ct, _, err := EncryptQueryE(kp.PublicKey, query)
		if err != nil {
			b.Fatal(err)
		}
		ciphertexts[i] = ct
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := kp.DecryptQueryE(ciphertexts[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESGCM_Seal(b *testing.B) {
	kr := make([]byte, 16)
	rand.Read(kr)
	response := make([]byte, benchResponseSize)
	rand.Read(response)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptCachedResponse(kr, response)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESGCM_Open(b *testing.B) {
	kr := make([]byte, 16)
	rand.Read(kr)
	response := make([]byte, benchResponseSize)
	rand.Read(response)

	// Pre-encrypt
	blob, err := EncryptCachedResponse(kr, response)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptCachedResponse(kr, blob)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAESGCM_Seal_PreNonce isolates the pure AES-GCM Seal primitive cost
// by pre-generating nonces outside the timed loop and caching the cipher.
// Contrast with BenchmarkAESGCM_Seal, which includes per-call cipher
// construction, nonce generation via crypto/rand, and a result-buffer
// allocation+copy.
func BenchmarkAESGCM_Seal_PreNonce(b *testing.B) {
	kr := make([]byte, 16)
	rand.Read(kr)
	response := make([]byte, benchResponseSize)
	rand.Read(response)

	block, err := aes.NewCipher(kr[:16])
	if err != nil {
		b.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	nonces := make([][]byte, b.N)
	for i := range nonces {
		nonces[i] = make([]byte, gcm.NonceSize())
		rand.Read(nonces[i])
	}
	dst := make([]byte, 0, benchResponseSize+gcm.Overhead())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gcm.Seal(dst[:0], nonces[i], response, nil)
	}
}

// BenchmarkNonceGen_Only isolates the cost of crypto/rand.Read for a
// 12-byte AES-GCM nonce. Under EGo/SGX this hits an OCALL-backed CSPRNG
// path that dominates the AES-GCM Seal function's SGX overhead.
func BenchmarkNonceGen_Only(b *testing.B) {
	nonce := make([]byte, 12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rand.Read(nonce); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519_Sign(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 256) // representative cache-insert bundle
	rand.Read(data)
	hash := sha256.Sum256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, hash[:])
	}
}

func BenchmarkEd25519_Verify(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 256)
	rand.Read(data)
	hash := sha256.Sum256(data)
	sig := ed25519.Sign(priv, hash[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, hash[:], sig)
	}
}
