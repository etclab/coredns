package codohtarget

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Benchmark data
var (
	benchQuery = "example.com.:1"
	benchSalt  []byte
)

func init() {
	benchSalt = make([]byte, 32)
	rand.Read(benchSalt)
}

// =============================================================================
// Current MLE KDF (Argon2id with production parameters)
// =============================================================================

func BenchmarkMLE_Current(b *testing.B) {
	// Current production parameters: 64MB, 3 iterations, 1 thread
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveMLEKey(benchQuery, benchSalt)
	}
}

// =============================================================================
// Argon2id variants - Memory parameter sweep
// =============================================================================

func BenchmarkArgon2id_16MB_3iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 16*1024, 1, 32)
	}
}

func BenchmarkArgon2id_32MB_3iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 32*1024, 1, 32)
	}
}

func BenchmarkArgon2id_64MB_3iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 64*1024, 1, 32)
	}
}

func BenchmarkArgon2id_128MB_3iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 128*1024, 1, 32)
	}
}

func BenchmarkArgon2id_256MB_3iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 256*1024, 1, 32)
	}
}

// =============================================================================
// Argon2id variants - Iteration parameter sweep (with 64MB)
// =============================================================================

func BenchmarkArgon2id_64MB_1iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 1, 64*1024, 1, 32)
	}
}

func BenchmarkArgon2id_64MB_2iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 2, 64*1024, 1, 32)
	}
}

func BenchmarkArgon2id_64MB_4iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 4, 64*1024, 1, 32)
	}
}

func BenchmarkArgon2id_64MB_6iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 6, 64*1024, 1, 32)
	}
}

// =============================================================================
// Argon2id variants - Thread parameter sweep (with 64MB, 3 iter)
// =============================================================================

func BenchmarkArgon2id_64MB_3iter_2threads(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 64*1024, 2, 32)
	}
}

func BenchmarkArgon2id_64MB_3iter_4threads(b *testing.B) {
	for i := 0; i < b.N; i++ {
		argon2.IDKey([]byte(benchQuery), benchSalt, 3, 64*1024, 4, 32)
	}
}

// =============================================================================
// Alternative KDFs for comparison
// =============================================================================

// HKDF - Very fast, no memory hardness (NOT suitable for rate limiting)
func BenchmarkHKDF_SHA256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		reader := hkdf.New(sha256.New, []byte(benchQuery), benchSalt, []byte("mle-key"))
		key := make([]byte, 32)
		reader.Read(key)
	}
}

// PBKDF2 - CPU-bound, no memory hardness
func BenchmarkPBKDF2_10000iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pbkdf2.Key([]byte(benchQuery), benchSalt, 10000, 32, sha256.New)
	}
}

func BenchmarkPBKDF2_100000iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pbkdf2.Key([]byte(benchQuery), benchSalt, 100000, 32, sha256.New)
	}
}

func BenchmarkPBKDF2_500000iter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pbkdf2.Key([]byte(benchQuery), benchSalt, 500000, 32, sha256.New)
	}
}

// Scrypt - Memory-hard alternative to Argon2
func BenchmarkScrypt_N16384_r8_p1(b *testing.B) {
	// N=16384, r=8, p=1 -> ~16MB memory
	for i := 0; i < b.N; i++ {
		scrypt.Key([]byte(benchQuery), benchSalt, 16384, 8, 1, 32)
	}
}

func BenchmarkScrypt_N32768_r8_p1(b *testing.B) {
	// N=32768, r=8, p=1 -> ~32MB memory
	for i := 0; i < b.N; i++ {
		scrypt.Key([]byte(benchQuery), benchSalt, 32768, 8, 1, 32)
	}
}

func BenchmarkScrypt_N65536_r8_p1(b *testing.B) {
	// N=65536, r=8, p=1 -> ~64MB memory
	for i := 0; i < b.N; i++ {
		scrypt.Key([]byte(benchQuery), benchSalt, 65536, 8, 1, 32)
	}
}

// =============================================================================
// Baseline operations for comparison
// =============================================================================

// SHA256 - Baseline hash operation
func BenchmarkSHA256(b *testing.B) {
	data := append([]byte(benchQuery), benchSalt...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sha256.Sum256(data)
	}
}

// Full MLE operation (KDF + tag + encrypt)
func BenchmarkMLE_FullOperation(b *testing.B) {
	plaintext := make([]byte, 512) // Typical DNS response size
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := DeriveMLEKey(benchQuery, benchSalt)
		_ = ComputeMLETag(key)
		MLEEncrypt(key, plaintext)
	}
}

// Just MLE encrypt (without KDF) for comparison
func BenchmarkMLE_EncryptOnly(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := make([]byte, 512)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MLEEncrypt(key, plaintext)
	}
}