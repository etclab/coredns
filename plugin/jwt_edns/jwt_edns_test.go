package jwt_edns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	golog "log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/golang-jwt/jwt/v5"
	"github.com/miekg/dns"
)

func TestJwtEdnsWithoutPublicKey(t *testing.T) {
	// Create plugin without public key
	j := &JwtEdns{Next: test.ErrorHandler(), publicKey: nil}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Should refuse all requests when no public key
	rcode, err := j.ServeDNS(ctx, rec, r)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if rcode != dns.RcodeRefused {
		t.Errorf("Expected REFUSED when no public key, got rcode: %d", rcode)
	}

	logOutput := b.String()
	if !strings.Contains(logOutput, "JWT validation required but no public key configured") {
		t.Errorf("Expected no public key log, got: %s", logOutput)
	}
}

func TestJwtEdnsWithoutEDNS(t *testing.T) {
	for _, algo := range []string{"rsa", "ecdsa", "eddsa"} {
		t.Run(algo, func(t *testing.T) {
			// Setup test keys
			_, publicKeyPath := setupTestKeys(t, algo)
			defer os.Remove(publicKeyPath)

			// Load public key
			os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyPath)
			defer os.Unsetenv("JWT_PUBLIC_KEY_PATH")
			publicKey, err := loadPublicKeyFromEnvWithAlgorithm(algo)
			if err != nil {
				t.Fatalf("Failed to load public key for %s: %v", algo, err)
			}

			j := &JwtEdns{Next: test.ErrorHandler(), publicKey: publicKey}

			b := &bytes.Buffer{}
			golog.SetOutput(b)

			ctx := context.TODO()
			r := new(dns.Msg)
			r.SetQuestion("example.org.", dns.TypeA)
			// No EDNS0 at all
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode, err := j.ServeDNS(ctx, rec, r)
			if err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}

			if rcode != dns.RcodeRefused {
				t.Errorf("Expected REFUSED when no EDNS for %s, got rcode: %d", algo, rcode)
			}

			logOutput := b.String()
			if !strings.Contains(logOutput, "No EDNS0 support - JWT token required") {
				t.Errorf("Expected no EDNS log for %s, got: %s", algo, logOutput)
			}
		})
	}
}

func TestJwtEdnsWithoutJWTToken(t *testing.T) {
	for _, algo := range []string{"rsa", "ecdsa", "eddsa"} {
		t.Run(algo, func(t *testing.T) {
			// Setup test keys
			_, publicKeyPath := setupTestKeys(t, algo)
			defer os.Remove(publicKeyPath)

			os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyPath)
			defer os.Unsetenv("JWT_PUBLIC_KEY_PATH")

			publicKey, err := loadPublicKeyFromEnvWithAlgorithm(algo)
			if err != nil {
				t.Fatalf("Failed to load public key for %s: %v", algo, err)
			}

			j := &JwtEdns{Next: test.ErrorHandler(), publicKey: publicKey}

			b := &bytes.Buffer{}
			golog.SetOutput(b)

			ctx := context.TODO()
			r := new(dns.Msg)
			r.SetQuestion("example.org.", dns.TypeA)

			// Add EDNS0 but without JWT option 65001
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			r.Extra = []dns.RR{opt}

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode, err := j.ServeDNS(ctx, rec, r)
			if err != nil {
				t.Errorf("Expected no error for %s, got: %v", algo, err)
			}

			if rcode != dns.RcodeRefused {
				t.Errorf("Expected REFUSED when no JWT token for %s, got rcode: %d", algo, rcode)
			}

			logOutput := b.String()
			if !strings.Contains(logOutput, "No JWT token found in EDNS options - JWT token required") {
				t.Errorf("Expected no JWT token log for %s, got: %s", algo, logOutput)
			}
		})
	}
}

// setupTestKeys creates a temporary key pair for testing based on the specified algorithm
func setupTestKeys(t *testing.T, algorithm string) (string, string) {
	var privateKeyPEM []byte
	var publicKeyPEM []byte

	switch algorithm {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA private key: %v", err)
		}
		publicKey := &privateKey.PublicKey
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatalf("Failed to marshal RSA public key: %v", err)
		}
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})
	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA private key: %v", err)
		}
		publicKey := &privateKey.PublicKey
		privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			t.Fatalf("Failed to marshal ECDSA private key: %v", err)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatalf("Failed to marshal ECDSA public key: %v", err)
		}
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})
	case "eddsa":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 private key: %v", err)
		}
		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			t.Fatalf("Failed to marshal Ed25519 private key: %v", err)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		// Ed25519 public keys are raw 32-byte keys, not marshaled via x509
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKey,
		})
	default:
		t.Fatalf("Unsupported algorithm: %s", algorithm)
	}

	// Write public key to temporary file
	tmpfile, err := os.CreateTemp("", "jwt_test_public_*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file for %s: %v", algorithm, err)
	}
	defer tmpfile.Close()

	if _, err := tmpfile.Write(publicKeyPEM); err != nil {
		t.Fatalf("Failed to write public key for %s: %v", algorithm, err)
	}

	return string(privateKeyPEM), tmpfile.Name()
}

// createTestJWT creates a valid JWT token for testing
func createTestJWT(privateKeyPEM string, algorithm string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", jwt.ErrInvalidKey
	}

	var signingMethod jwt.SigningMethod
	var privateKey interface{}
	var err error

	switch algorithm {
	case "rsa":
		signingMethod = jwt.SigningMethodRS256
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "ecdsa":
		signingMethod = jwt.SigningMethodES256
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "eddsa":
		signingMethod = jwt.SigningMethodEdDSA
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return "", err
	}

	// Create JWT with required claims for CoreDNS
	claims := JWTClaims{
		ClientID:     "test-client",
		Permissions:  []string{"query"},
		AllowedZones: []string{"example.org", "test.com"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "jwt-tools",
			Subject:   "test-client",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(privateKey)
}

// createTestJWTWithoutPermissions creates a JWT token without query permission
func createTestJWTWithoutPermissions(privateKeyPEM string, algorithm string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", jwt.ErrInvalidKey
	}

	var signingMethod jwt.SigningMethod
	var privateKey interface{}
	var err error

	switch algorithm {
	case "rsa":
		signingMethod = jwt.SigningMethodRS256
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "ecdsa":
		signingMethod = jwt.SigningMethodES256
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "eddsa":
		signingMethod = jwt.SigningMethodEdDSA
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return "", err
	}

	claims := JWTClaims{
		ClientID:    "test-client",
		Permissions: []string{"admin"}, // No "query" permission
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "jwt-tools",
			Subject:   "test-client",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(privateKey)
}

func TestJwtEdnsWithValidJWT(t *testing.T) {
	for _, algo := range []string{"rsa", "ecdsa", "eddsa"} {
		t.Run(algo, func(t *testing.T) {
			// Setup test keys
			privateKeyPEM, publicKeyPath := setupTestKeys(t, algo)
			defer os.Remove(publicKeyPath)

			// Set environment variable
			originalEnv := os.Getenv("JWT_PUBLIC_KEY_PATH")
			os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyPath)
			defer os.Setenv("JWT_PUBLIC_KEY_PATH", originalEnv)

			// Load public key
			publicKey, err := loadPublicKeyFromEnvWithAlgorithm(algo)
			if err != nil {
				t.Fatalf("Failed to load public key for %s: %v", algo, err)
			}

			// Create valid JWT token
			validToken, err := createTestJWT(privateKeyPEM, algo)
			if err != nil {
				t.Fatalf("Failed to create test JWT for %s: %v", algo, err)
			}

			// Create plugin with public key
			j := &JwtEdns{Next: test.ErrorHandler(), publicKey: publicKey}

			// Setup logging
			b := &bytes.Buffer{}
			golog.SetOutput(b)

			ctx := context.TODO()
			r := new(dns.Msg)
			r.SetQuestion("example.org.", dns.TypeA)

			// Add EDNS0 with valid JWT token
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT

			localOpt := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(validToken)}
			opt.Option = []dns.EDNS0{localOpt}
			r.Extra = []dns.RR{opt}

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Call plugin
			rcode, err := j.ServeDNS(ctx, rec, r)
			if err != nil {
				t.Errorf("Expected no error for %s, got: %v", algo, err)
			}

			// Should not return REFUSED for valid token
			if rcode == dns.RcodeRefused {
				t.Errorf("Expected valid JWT to not return REFUSED for %s, got rcode: %d", algo, rcode)
			}

			// Check logs
			logOutput := b.String()
			if !strings.Contains(logOutput, "JWT token validated successfully") {
				t.Errorf("Expected successful validation log for %s, got: %s", algo, logOutput)
			}
		})
	}
}

func TestJwtEdnsWithInvalidJWT(t *testing.T) {
	for _, algo := range []string{"rsa", "ecdsa", "eddsa"} {
		t.Run(algo, func(t *testing.T) {
			// Setup test keys
			_, publicKeyPath := setupTestKeys(t, algo)
			defer os.Remove(publicKeyPath)

			// Set environment variable
			originalEnv := os.Getenv("JWT_PUBLIC_KEY_PATH")
			os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyPath)
			defer os.Setenv("JWT_PUBLIC_KEY_PATH", originalEnv)

			// Load public key
			publicKey, err := loadPublicKeyFromEnvWithAlgorithm(algo)
			if err != nil {
				t.Fatalf("Failed to load public key for %s: %v", algo, err)
			}

			// Create plugin with public key
			j := &JwtEdns{Next: test.ErrorHandler(), publicKey: publicKey}

			// Setup logging
			b := &bytes.Buffer{}
			golog.SetOutput(b)

			ctx := context.TODO()
			r := new(dns.Msg)
			r.SetQuestion("example.org.", dns.TypeA)

			// Add EDNS0 with invalid JWT token
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT

			invalidToken := "invalid.jwt.token"
			localOpt := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(invalidToken)}
			opt.Option = []dns.EDNS0{localOpt}
			r.Extra = []dns.RR{opt}

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Call plugin
			rcode, err := j.ServeDNS(ctx, rec, r)
			if err != nil {
				t.Errorf("Expected no error for %s, got: %v", algo, err)
			}

			// Should return REFUSED for invalid token
			if rcode != dns.RcodeRefused {
				t.Errorf("Expected REFUSED for invalid JWT for %s, got rcode: %d", algo, rcode)
			}

			// Check logs
			logOutput := b.String()
			if !strings.Contains(logOutput, "JWT validation failed") {
				t.Errorf("Expected validation failure log for %s, got: %s", algo, logOutput)
			}
		})
	}
}

func TestJwtEdnsWithMissingPublicKey(t *testing.T) {
	// Ensure no public key path is set
	originalEnv := os.Getenv("JWT_PUBLIC_KEY_PATH")
	os.Unsetenv("JWT_PUBLIC_KEY_PATH")
	defer os.Setenv("JWT_PUBLIC_KEY_PATH", originalEnv)

	// Create plugin without public key
	j := &JwtEdns{Next: test.ErrorHandler(), publicKey: nil}

	// Setup logging
	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)

	// Add EDNS0 with JWT token
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT

	someToken := "some.jwt.token"
	localOpt := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(someToken)}
	opt.Option = []dns.EDNS0{localOpt}
	r.Extra = []dns.RR{opt}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call plugin
	rcode, err := j.ServeDNS(ctx, rec, r)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Should return REFUSED when public key is not available
	if rcode != dns.RcodeRefused {
		t.Errorf("Expected REFUSED when public key missing, got rcode: %d", rcode)
	}

	// Check logs
	logOutput := b.String()
	if !strings.Contains(logOutput, "JWT validation required but no public key configured") {
		t.Errorf("Expected no public key configured log, got: %s", logOutput)
	}
}

func TestJwtEdnsWithoutQueryPermission(t *testing.T) {
	for _, algo := range []string{"rsa", "ecdsa", "eddsa"} {
		t.Run(algo, func(t *testing.T) {
			// Setup test keys
			privateKeyPEM, publicKeyPath := setupTestKeys(t, algo)
			defer os.Remove(publicKeyPath)

			// Set environment variable
			originalEnv := os.Getenv("JWT_PUBLIC_KEY_PATH")
			os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyPath)
			defer os.Setenv("JWT_PUBLIC_KEY_PATH", originalEnv)

			// Load public key
			publicKey, err := loadPublicKeyFromEnvWithAlgorithm(algo)
			if err != nil {
				t.Fatalf("Failed to load public key for %s: %v", algo, err)
			}

			// Create JWT token without query permission
			invalidToken, err := createTestJWTWithoutPermissions(privateKeyPEM, algo)
			if err != nil {
				t.Fatalf("Failed to create test JWT for %s: %v", algo, err)
			}

			// Create plugin with public key
			j := &JwtEdns{Next: test.ErrorHandler(), publicKey: publicKey}

			// Setup logging
			b := &bytes.Buffer{}
			golog.SetOutput(b)

			ctx := context.TODO()
			r := new(dns.Msg)
			r.SetQuestion("example.org.", dns.TypeA)

			// Add EDNS0 with JWT token lacking query permission
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT

			localOpt := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(invalidToken)}
			opt.Option = []dns.EDNS0{localOpt}
			r.Extra = []dns.RR{opt}

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Call plugin
			rcode, err := j.ServeDNS(ctx, rec, r)
			if err != nil {
				t.Errorf("Expected no error for %s, got: %v", algo, err)
			}

			// Should return REFUSED for token without query permission
			if rcode != dns.RcodeRefused {
				t.Errorf("Expected REFUSED for JWT without query permission for %s, got rcode: %d", algo, rcode)
			}

			// Check logs
			logOutput := b.String()
			if !strings.Contains(logOutput, "missing required 'query' permission") {
				t.Errorf("Expected missing query permission log for %s, got: %s", algo, logOutput)
			}
		})
	}
}

func TestJwtEdnsZoneRestriction(t *testing.T) {
	for _, algo := range []string{"rsa", "ecdsa", "eddsa"} {
		t.Run(algo, func(t *testing.T) {
			// Setup test keys
			privateKeyPEM, publicKeyPath := setupTestKeys(t, algo)
			defer os.Remove(publicKeyPath)

			// Set environment variable
			originalEnv := os.Getenv("JWT_PUBLIC_KEY_PATH")
			os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyPath)
			defer os.Setenv("JWT_PUBLIC_KEY_PATH", originalEnv)

			// Load public key
			publicKey, err := loadPublicKeyFromEnvWithAlgorithm(algo)
			if err != nil {
				t.Fatalf("Failed to load public key for %s: %v", algo, err)
			}

			// Create valid JWT token (allowed zones: example.org, test.com)
			validToken, err := createTestJWT(privateKeyPEM, algo)
			if err != nil {
				t.Fatalf("Failed to create test JWT for %s: %v", algo, err)
			}

			// Create plugin with public key
			j := &JwtEdns{Next: test.ErrorHandler(), publicKey: publicKey}

			// Test 1: Query for allowed zone (example.org) - should succeed
			b := &bytes.Buffer{}
			golog.SetOutput(b)

			ctx := context.TODO()
			r := new(dns.Msg)
			r.SetQuestion("example.org.", dns.TypeA)

			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT

			localOpt := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(validToken)}
			opt.Option = []dns.EDNS0{localOpt}
			r.Extra = []dns.RR{opt}

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode, err := j.ServeDNS(ctx, rec, r)
			if err != nil {
				t.Errorf("Expected no error for %s, got: %v", algo, err)
			}

			if rcode == dns.RcodeRefused {
				t.Errorf("Expected success for allowed zone for %s, got REFUSED", algo)
			}

			// Test 2: Query for disallowed zone - should fail
			b.Reset()
			r2 := new(dns.Msg)
			r2.SetQuestion("forbidden.zone.", dns.TypeA)

			opt2 := new(dns.OPT)
			opt2.Hdr.Name = "."
			opt2.Hdr.Rrtype = dns.TypeOPT

			localOpt2 := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(validToken)}
			opt2.Option = []dns.EDNS0{localOpt2}
			r2.Extra = []dns.RR{opt2}

			rec2 := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode2, err := j.ServeDNS(ctx, rec2, r2)
			if err != nil {
				t.Errorf("Expected no error for %s, got: %v", algo, err)
			}

			if rcode2 != dns.RcodeRefused {
				t.Errorf("Expected REFUSED for disallowed zone for %s, got rcode: %d", algo, rcode2)
			}

			logOutput := b.String()
			if !strings.Contains(logOutput, "not in allowed zones") {
				t.Errorf("Expected zone restriction log for %s, got: %s", algo, logOutput)
			}
		})
	}
}
