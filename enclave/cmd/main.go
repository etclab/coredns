// CODoH Enclave - SGX enclave for cache lookup and response encryption.
// Build with EGo: ego-go build -o enclave ./enclave/cmd
// Dev build: go build -o enclave-sim ./enclave/cmd
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/coredns/coredns/enclave"
)

func main() {
	socketPath := flag.String("socket", "/tmp/codoh-enclave.sock", "Unix socket path")
	httpsPort := flag.Int("https-port", 8444, "HTTPS port for attestation server")
	mode := flag.String("mode", "ipc", "Operating mode: 'ipc' (default, 3-process CODoH) or 'proxy' (2-process CODoH-base)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (proxy mode)")
	tlsKey := flag.String("tls-key", "", "TLS key file (proxy mode)")
	targetURL := flag.String("target", "", "Target URL (proxy mode, e.g., 'https://127.0.0.1:10444')")
	flag.Parse()

	log.Println("CODoH Enclave starting...")

	// Generate HPKE keypair
	keypair, err := enclave.GenerateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	pubBytes, _ := keypair.PublicKeyBytes()
	log.Printf("Public key: %s", base64.StdEncoding.EncodeToString(pubBytes))

	// Proxy mode: lightweight 2-process architecture for CODoH-base (Config 3)
	if *mode == "proxy" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("Proxy mode requires -tls-cert and -tls-key flags")
		}
		if *targetURL == "" {
			log.Fatal("Proxy mode requires -target flag (e.g., 'https://127.0.0.1:10444')")
		}

		cfg := enclave.DefaultConfig()
		loadOptionalEnvSettings(cfg)

		cache := enclave.NewLRUCache(cfg.CacheSize)
		log.Printf("Proxy mode: LRU cache capacity=%d", cfg.CacheSize)

		server := NewProxyServer(keypair, cache, *targetURL, *tlsCert, *tlsKey, *httpsPort)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Println("Shutting down proxy...")
			os.Exit(0)
		}()

		if err := server.Start(); err != nil {
			log.Fatalf("Proxy server error: %v", err)
		}
		return
	}

	// IPC mode: full 3-process CODoH architecture (Configs 4-7)

	// Channel for receiving provisioned data (signing pubkey only)
	provisionCh := make(chan enclave.ProvisionData, 1)

	// Try to generate quote to determine if we're in SGX mode
	quote, quoteErr := enclave.GenerateQuote(pubBytes)
	if quoteErr != nil {
		// Simulation mode: no provisioning needed for signing key (optional)
		log.Printf("SGX quote generation failed (simulation mode): %v", quoteErr)
		// In simulation mode, signing pubkey can be loaded from env/file
		sigPubKey := loadSimSigningPubKey()
		provisionCh <- enclave.ProvisionData{SigningPublicKey: sigPubKey}
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

	// Wait for provisioning data
	log.Println("Waiting for provisioning...")
	provData := <-provisionCh
	log.Println("Provisioning complete, initializing enclave...")

	// Load config
	cfg := enclave.DefaultConfig()
	cfg.SocketPath = *socketPath
	loadOptionalEnvSettings(cfg)

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
		log.Printf("ORAM cache: capacity=%d", cfg.CacheSize)
	} else {
		cache = enclave.NewLRUCache(cfg.CacheSize)
		log.Printf("LRU cache: capacity=%d", cfg.CacheSize)
	}

	// Remove stale socket
	os.Remove(cfg.SocketPath)

	// Create handler
	handler := &EnclaveHandler{
		keypair:             keypair,
		cache:               cache,
		oramCache:           oramCache,
		targetSigningPubKey: provData.SigningPublicKey,
		defaultPadSize:      cfg.DefaultPadSize,
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

// loadOptionalEnvSettings loads optional settings from environment variables.
func loadOptionalEnvSettings(cfg *enclave.Config) {
	if size := os.Getenv("CODOH_CACHE_SIZE"); size != "" {
		if n, err := strconv.Atoi(size); err == nil {
			cfg.CacheSize = n
		}
	}
	if useORAM := os.Getenv("CODOH_USE_ORAM"); useORAM == "true" || useORAM == "1" {
		cfg.UseORAMCache = true
	}
	if blockSize := os.Getenv("CODOH_ORAM_BLOCK_SIZE"); blockSize != "" {
		if n, err := strconv.Atoi(blockSize); err == nil {
			cfg.ORAMBlockSize = n
		}
	}
	if padSize := os.Getenv("CODOH_DEFAULT_PAD_SIZE"); padSize != "" {
		if n, err := strconv.Atoi(padSize); err == nil {
			cfg.DefaultPadSize = n
		}
	}
}

// loadSimSigningPubKey loads the target's Ed25519 signing pubkey from env for simulation mode.
func loadSimSigningPubKey() []byte {
	if b64 := os.Getenv("CODOH_TARGET_SIGNING_PUBKEY"); b64 != "" {
		pubKey, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Printf("WARNING: CODOH_TARGET_SIGNING_PUBKEY invalid base64: %v", err)
			return nil
		}
		if len(pubKey) != ed25519.PublicKeySize {
			log.Printf("WARNING: CODOH_TARGET_SIGNING_PUBKEY wrong length: %d", len(pubKey))
			return nil
		}
		return pubKey
	}
	log.Println("WARNING: No target signing pubkey configured (signature verification disabled)")
	return nil
}

// EnclaveHandler implements enclave.RequestHandler.
type EnclaveHandler struct {
	keypair             *enclave.EnclaveKeypair
	cache               enclave.Cache
	oramCache           *enclave.ORAMCache       // nil if not using ORAM (for stash monitoring)
	targetSigningPubKey ed25519.PublicKey         // Target's Ed25519 public key
	defaultPadSize      int
}

// HandleProcess decrypts Q_E, looks up cache, returns encrypted response or dummy.
func (h *EnclaveHandler) HandleProcess(qe string) *enclave.Response {
	// Decode Q_E
	qeBytes, err := base64.StdEncoding.DecodeString(qe)
	if err != nil {
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidBlob,
		}
	}

	// Decrypt Q_E and derive session key k_r
	query, kr, err := h.keypair.DecryptQueryE(qeBytes)
	if err != nil {
		log.Printf("DecryptQueryE failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrHPKEError,
		}
	}

	canonicalQuery := string(query)

	// Cache lookup
	if cachedResp, ok := h.cache.Get(canonicalQuery); ok {
		// Cache hit — encrypt under session key k_r
		encrypted, err := enclave.EncryptCachedResponse(kr, cachedResp)
		if err != nil {
			log.Printf("EncryptCachedResponse failed: %v", err)
			// Fall through to dummy
		} else {
			h.logCacheOp("hit", canonicalQuery)
			return &enclave.Response{
				Status:   enclave.StatusHit,
				Response: base64.StdEncoding.EncodeToString(encrypted),
			}
		}
	}

	// Cache miss — return dummy (indistinguishable from hit)
	dummy := enclave.GenerateDummyResponse(h.defaultPadSize)
	h.logCacheOp("miss", canonicalQuery)
	return &enclave.Response{
		Status:   enclave.StatusMiss,
		Response: base64.StdEncoding.EncodeToString(dummy),
	}
}

// HandleStoreEncrypted decrypts cache-insert bundle, verifies signature, stores in cache.
func (h *EnclaveHandler) HandleStoreEncrypted(encryptedBlob, signature string) *enclave.Response {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBlob)
	if err != nil {
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidBlob,
		}
	}

	// Decrypt with enclave's private key
	plaintext, err := h.keypair.Decrypt(ciphertext)
	if err != nil {
		log.Printf("StoreEncrypted: decrypt failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrDecryptFailed,
		}
	}

	// Verify signature if signing key is configured
	if len(h.targetSigningPubKey) > 0 {
		if signature == "" {
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  enclave.ErrInvalidSignature,
			}
		}

		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  enclave.ErrInvalidSignature,
			}
		}

		// Verify: Sign(H(plaintext_bundle))
		hash := sha256.Sum256(plaintext)
		if !ed25519.Verify(h.targetSigningPubKey, hash[:], sigBytes) {
			log.Printf("StoreEncrypted: signature verification failed")
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  enclave.ErrInvalidSignature,
			}
		}
	}

	// Parse bundle
	bundle, err := enclave.ParseCacheInsertBundle(plaintext)
	if err != nil {
		log.Printf("StoreEncrypted: parse bundle failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidBlob,
		}
	}

	// Store in cache
	ttlDuration := time.Duration(bundle.TTL) * time.Second
	h.cache.Put(bundle.CanonicalQuery, bundle.DNSResponse, ttlDuration)
	h.logCacheOp("store", bundle.CanonicalQuery)

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

// logCacheOp logs cache operations with stash size when using ORAM.
func (h *EnclaveHandler) logCacheOp(op, query string) {
	if h.oramCache != nil {
		log.Printf("Cache %s for %s, cache_size=%d, stash_size=%d", op, query, h.cache.Size(), h.oramCache.StashSize())
	} else {
		log.Printf("Cache %s for %s, cache_size=%d", op, query, h.cache.Size())
	}
}
