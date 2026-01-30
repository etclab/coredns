// CODoH Enclave - SGX enclave for token verification and caching.
// Build with EGo: ego-go build -o enclave ./enclave/cmd
// Dev build: go build -o enclave-dev ./enclave/cmd
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coredns/coredns/enclave"
)

func main() {
	socketPath := flag.String("socket", "/tmp/codoh-enclave.sock", "Unix socket path")
	secretFile := flag.String("secret", "", "Path to master secret file (hex-encoded, for simulation mode)")
	httpsPort := flag.Int("https-port", 8444, "HTTPS port for attestation server")
	flag.Parse()

	log.Println("CODoH Enclave starting...")

	// Generate HPKE keypair
	keypair, err := enclave.GenerateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	pubBytes, _ := keypair.PublicKeyBytes()
	log.Printf("Public key: %s", base64.StdEncoding.EncodeToString(pubBytes))

	// Channel for receiving provisioned data
	provisionCh := make(chan enclave.ProvisionData, 1)

	// Try to generate quote to determine if we're in SGX mode
	quote, quoteErr := enclave.GenerateQuote(pubBytes)
	if quoteErr != nil {
		// Simulation mode: fall back to file/env-based secret
		log.Printf("SGX quote generation failed (simulation mode): %v", quoteErr)
		masterSecret, err := loadFallbackSecret(*socketPath, *secretFile)
		if err != nil {
			log.Fatalf("Failed to load fallback secret: %v", err)
		}
		provisionCh <- enclave.ProvisionData{MasterSecret: masterSecret}
	} else {
		// SGX mode: start attestation server and wait for provisioning
		log.Printf("SGX mode enabled, quote generated (%d bytes)", len(quote))
		attestServer := enclave.NewAttestationServer(*httpsPort, keypair, provisionCh)
		go func() {
			if err := attestServer.Start(); err != nil {
				log.Fatalf("Attestation server error: %v", err)
			}
		}()
		log.Printf("Attestation server starting on port %d, waiting for provisioning...", *httpsPort)
	}

	// Wait for provisioning data (blocks until provisioned)
	log.Println("Waiting for master secret provisioning...")
	provData := <-provisionCh
	log.Println("Provisioning data received, initializing enclave...")

	// Load config (now with provisioned secret)
	cfg := enclave.DefaultConfig()
	cfg.SocketPath = *socketPath
	cfg.MasterSecret = provData.MasterSecret

	// Try to override from environment (for epoch duration, cache size, etc.)
	if envCfg, err := enclave.LoadConfigFromEnv(); err == nil {
		cfg.EpochDuration = envCfg.EpochDuration
		cfg.CacheSize = envCfg.CacheSize
		cfg.UseORAMCache = envCfg.UseORAMCache
		cfg.ORAMBlockSize = envCfg.ORAMBlockSize
		// Don't override MasterSecret - we got it from provisioning
	}

	// Initialize epoch manager for token verification
	epochMgr, err := enclave.NewEpochManager(cfg.MasterSecret, cfg.EpochDuration)
	if err != nil {
		log.Fatalf("Failed to create epoch manager: %v", err)
	}
	log.Printf("Epoch manager initialized, current epoch: %d", epochMgr.CurrentEpoch())

	// Initialize spent set
	spentSet := enclave.NewSpentSet(epochMgr.CurrentEpoch())

	// Initialize cache
	var cache enclave.Cache
	var oramCache *enclave.ORAMCache
	if cfg.UseORAMCache {
		oramCfg := enclave.ORAMCacheConfig{
			Capacity:     cfg.CacheSize,
			BlockSize:    cfg.ORAMBlockSize,
			BucketSize:   5,
			ConstantTime: true,
		}
		var err error
		oramCache, err = enclave.NewORAMCache(oramCfg)
		if err != nil {
			log.Fatalf("Failed to create ORAM cache: %v", err)
		}
		cache = oramCache
		log.Printf("ORAM cache initialized with capacity %d, block size %d", cfg.CacheSize, cfg.ORAMBlockSize)
	} else {
		cache = enclave.NewLRUCache(cfg.CacheSize)
		log.Printf("LRU cache initialized with capacity %d", cfg.CacheSize)
	}

	// Remove stale socket
	os.Remove(cfg.SocketPath)

	// Create handler
	handler := &EnclaveHandler{
		keypair:             keypair,
		epochMgr:            epochMgr,
		spentSet:            spentSet,
		cache:               cache,
		oramCache:           oramCache,
		targetSigningPubKey: provData.SigningPublicKey,
		ready:               true, // Ready after provisioning
	}
	if len(provData.SigningPublicKey) > 0 {
		log.Printf("Target signing pubkey registered (%d bytes)", len(provData.SigningPublicKey))
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

	log.Printf("Enclave ready, listening on %s", cfg.SocketPath)
	if err := server.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// loadFallbackSecret loads master secret from file or environment (for simulation mode).
func loadFallbackSecret(socketPath, secretFile string) ([]byte, error) {
	// Try environment first
	cfg, err := enclave.LoadConfigFromEnv()
	if err == nil && len(cfg.MasterSecret) > 0 {
		return cfg.MasterSecret, nil
	}

	// Try file
	if secretFile != "" {
		return enclave.LoadMasterSecretFromFile(secretFile)
	}

	// Development fallback (NOT FOR PRODUCTION)
	log.Println("WARNING: Using default master secret for development")
	secret := make([]byte, 32)
	copy(secret, []byte("codoh-dev-secret-not-for-prod!!"))
	return secret, nil
}

// EnclaveHandler implements enclave.RequestHandler.
type EnclaveHandler struct {
	keypair             *enclave.EnclaveKeypair
	epochMgr            *enclave.EpochManager
	spentSet            *enclave.SpentSet
	cache               enclave.Cache
	oramCache           *enclave.ORAMCache // nil if not using ORAM (for stash monitoring)
	targetSigningPubKey ed25519.PublicKey  // Target's Ed25519 public key for signature verification
	ready               bool
	mu                  sync.RWMutex
}

// SetReady sets the ready status.
func (h *EnclaveHandler) SetReady(ready bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = ready
}

// HandleReady returns the ready status (for proxy to poll).
func (h *EnclaveHandler) HandleReady() *enclave.Response {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return &enclave.Response{
		Status: enclave.StatusOK,
		Ready:  h.ready,
	}
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
			h.logCacheOp("hit", blob.Query)
			return &enclave.Response{
				Status:   enclave.StatusHit,
				Response: base64.StdEncoding.EncodeToString(encrypted),
			}
		}
	}

	// Cache miss
	h.logCacheOp("miss", blob.Query)
	return &enclave.Response{
		Status: enclave.StatusMiss,
		Query:  blob.Query,
		Kc:     base64.StdEncoding.EncodeToString(blob.Kc),
	}
}

// HandleStoreEncrypted decrypts, verifies signature, and stores a cache entry from target.
// The response is HPKE-encrypted under the enclave's public key.
func (h *EnclaveHandler) HandleStoreEncrypted(query, encryptedResponse, signature, blobB string, ttl int) *enclave.Response {
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

	// Verify signature if signing key is configured
	if len(h.targetSigningPubKey) > 0 {
		if signature == "" {
			log.Printf("StoreEncrypted: signature required but not provided")
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  "signature_required",
			}
		}

		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			log.Printf("StoreEncrypted: invalid signature encoding")
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  "invalid_signature_encoding",
			}
		}

		// Compute signature input: H(response || query || blobB)
		toVerify := computeSignatureInput(plaintext, query, blobB)
		if !ed25519.Verify(h.targetSigningPubKey, toVerify, sigBytes) {
			log.Printf("StoreEncrypted: signature verification failed for query=%s", query)
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  "invalid_signature",
			}
		}
		log.Printf("StoreEncrypted: signature verified for query=%s", query)
	}

	// Store plaintext DNS in cache
	ttlDuration := time.Duration(ttl) * time.Second
	h.cache.Put(query, plaintext, nil, ttlDuration)
	h.logCacheOp("store", query)

	return &enclave.Response{Status: enclave.StatusOK}
}

// computeSignatureInput computes H(response || query || blobB) for signature verification.
func computeSignatureInput(response []byte, query, blobB string) []byte {
	h := sha256.New()
	h.Write(response)
	h.Write([]byte(query))
	h.Write([]byte(blobB))
	return h.Sum(nil)
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

// logCacheOp logs cache operations with stash size when using ORAM.
func (h *EnclaveHandler) logCacheOp(op, query string) {
	if h.oramCache != nil {
		log.Printf("Cache %s for %s, cache_size=%d, stash_size=%d", op, query, h.cache.Size(), h.oramCache.StashSize())
	} else {
		log.Printf("Cache %s for %s, cache_size=%d", op, query, h.cache.Size())
	}
}
