// CODoH Enclave - SGX enclave for token verification and caching.
// Build with EGo: ego-go build -o enclave ./enclave/cmd
// Dev build: go build -o enclave-dev ./enclave/cmd
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coredns/coredns/enclave"
)

func main() {
	socketPath := flag.String("socket", "/tmp/codoh-enclave.sock", "Unix socket path")
	secretFile := flag.String("secret", "", "Path to master secret file (hex-encoded)")
	flag.Parse()

	log.Println("CODoH Enclave starting...")

	// Load config
	cfg, err := loadConfig(*socketPath, *secretFile)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	// Generate HPKE keypair
	keypair, err := enclave.GenerateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	pubBytes, _ := keypair.PublicKeyBytes()
	log.Printf("Public key: %s", base64.StdEncoding.EncodeToString(pubBytes))

	// Initialize epoch manager for token verification
	epochMgr, err := enclave.NewEpochManager(cfg.MasterSecret, cfg.EpochDuration)
	if err != nil {
		log.Fatalf("Failed to create epoch manager: %v", err)
	}
	log.Printf("Epoch manager initialized, current epoch: %d", epochMgr.CurrentEpoch())

	// Initialize spent set
	spentSet := enclave.NewSpentSet(epochMgr.CurrentEpoch())

	// Initialize cache
	cache := enclave.NewLRUCache(cfg.CacheSize)
	log.Printf("Cache initialized with capacity %d", cfg.CacheSize)

	// Remove stale socket
	os.Remove(cfg.SocketPath)

	// Create handler
	handler := &EnclaveHandler{
		keypair:  keypair,
		epochMgr: epochMgr,
		spentSet: spentSet,
		cache:    cache,
	}

	// Start IPC server
	server, err := enclave.NewIPCServer(cfg.SocketPath, handler)
	if err != nil {
		log.Fatalf("Failed to create IPC server: %v", err)
	}
	defer server.Close()

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		server.Close()
		os.Remove(cfg.SocketPath)
		os.Exit(0)
	}()

	log.Printf("Listening on %s", cfg.SocketPath)
	if err := server.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func loadConfig(socketPath, secretFile string) (*enclave.Config, error) {
	// Try environment first
	cfg, err := enclave.LoadConfigFromEnv()
	if err == nil {
		if socketPath != "" {
			cfg.SocketPath = socketPath
		}
		return cfg, nil
	}

	// Fall back to file-based config
	cfg = enclave.DefaultConfig()
	cfg.SocketPath = socketPath

	if secretFile != "" {
		secret, err := enclave.LoadMasterSecretFromFile(secretFile)
		if err != nil {
			return nil, err
		}
		cfg.MasterSecret = secret
	} else {
		// For development, use a default secret (NOT FOR PRODUCTION)
		log.Println("WARNING: Using default master secret for development")
		cfg.MasterSecret = make([]byte, 32)
		copy(cfg.MasterSecret, []byte("codoh-dev-secret-not-for-prod!!"))
	}

	return cfg, nil
}

// EnclaveHandler implements enclave.RequestHandler.
type EnclaveHandler struct {
	keypair  *enclave.EnclaveKeypair
	epochMgr *enclave.EpochManager
	spentSet *enclave.SpentSet
	cache    *enclave.LRUCache
}

func (h *EnclaveHandler) HandleProcess(blobB, clientIP string) *enclave.Response {
	// Check epoch rotation
	if rotated, err := h.epochMgr.RotateIfNeeded(); err != nil {
		log.Printf("Epoch rotation error: %v", err)
	} else if rotated {
		newEpoch := h.epochMgr.CurrentEpoch()
		log.Printf("Epoch rotated to %d, clearing spent set", newEpoch)
		h.spentSet.Clear(newEpoch)
	}

	// Decode blob B
	blobBytes, err := base64.StdEncoding.DecodeString(blobB)
	if err != nil {
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidBlob,
		}
	}

	// Decrypt blob B
	blob, err := h.keypair.DecryptBlobB(blobBytes)
	if err != nil {
		log.Printf("Decrypt failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrDecryptFailed,
		}
	}

	log.Printf("Decrypted blob: epoch=%d query=%s client=%s", blob.Epoch, blob.Query, clientIP)

	// Verify token epoch
	if blob.Epoch != h.epochMgr.CurrentEpoch() {
		log.Printf("Token expired: token epoch %d != current %d", blob.Epoch, h.epochMgr.CurrentEpoch())
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrTokenExpired,
		}
	}

	// Verify token (VOPRF output)
	if !h.epochMgr.Verify(blob.Epoch, blob.Input, blob.Token) {
		log.Printf("Token verification failed")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidToken,
		}
	}

	// Check spent set (combine input + token as unique identifier)
	tokenID := append(blob.Input, blob.Token...)
	if !h.spentSet.MarkSpent(tokenID) {
		log.Printf("Token already spent")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrTokenSpent,
		}
	}

	log.Printf("Token verified and marked spent, spent set size: %d", h.spentSet.Size())

	// Check cache for hit
	if cachedResp, cachedKc, ok := h.cache.Get(blob.Query); ok {
		// Cache hit - re-encrypt response under client's k_c
		// The cached response was encrypted under the original k_c, so we need to
		// decrypt and re-encrypt. For simplicity, store plaintext and encrypt on hit.
		encrypted, err := enclave.EncryptResponse(blob.Kc, cachedResp)
		if err != nil {
			log.Printf("Failed to encrypt cached response: %v", err)
			// Fall through to miss
		} else {
			_ = cachedKc // unused, we encrypt with client's kc
			log.Printf("Cache hit for %s", blob.Query)
			return &enclave.Response{
				Status:   enclave.StatusHit,
				Response: base64.StdEncoding.EncodeToString(encrypted),
			}
		}
	}

	// Cache miss
	log.Printf("Cache miss for %s, cache size: %d", blob.Query, h.cache.Size())
	return &enclave.Response{
		Status: enclave.StatusMiss,
		Query:  blob.Query,
		Kc:     base64.StdEncoding.EncodeToString(blob.Kc),
	}
}

func (h *EnclaveHandler) HandleStore(query, response string, ttl int) *enclave.Response {
	// Decode response
	respBytes, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		log.Printf("Store: invalid response encoding")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  "invalid_response",
		}
	}

	// Store in cache (plaintext DNS response, encrypted on retrieval)
	ttlDuration := time.Duration(ttl) * time.Second
	h.cache.Put(query, respBytes, nil, ttlDuration)
	log.Printf("Stored in cache: query=%s ttl=%ds cache_size=%d", query, ttl, h.cache.Size())

	return &enclave.Response{Status: enclave.StatusOK}
}

// HandleStoreEncrypted decrypts and stores a cache entry from target.
// The response is HPKE-encrypted under the enclave's public key.
func (h *EnclaveHandler) HandleStoreEncrypted(query, encryptedResponse string, ttl int) *enclave.Response {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedResponse)
	if err != nil {
		log.Printf("StoreEncrypted: invalid base64 encoding")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  "invalid_encoding",
		}
	}

	// Decrypt with enclave's private key
	plaintext, err := h.keypair.Decrypt(ciphertext)
	if err != nil {
		log.Printf("StoreEncrypted: decrypt failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  "decrypt_failed",
		}
	}

	// Store plaintext DNS in cache
	ttlDuration := time.Duration(ttl) * time.Second
	h.cache.Put(query, plaintext, nil, ttlDuration)
	log.Printf("StoreEncrypted: stored in cache: query=%s ttl=%ds cache_size=%d", query, ttl, h.cache.Size())

	return &enclave.Response{Status: enclave.StatusOK}
}

func (h *EnclaveHandler) HandleGetPubKey() *enclave.Response {
	pubBytes, err := h.keypair.PublicKeyBytes()
	if err != nil {
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInternal,
		}
	}
	return &enclave.Response{
		Status: enclave.StatusOK,
		PubKey: base64.StdEncoding.EncodeToString(pubBytes),
	}
}

func (h *EnclaveHandler) HandleHealth() *enclave.Response {
	return &enclave.Response{Status: enclave.StatusOK}
}
