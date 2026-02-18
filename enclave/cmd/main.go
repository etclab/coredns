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
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/coredns/coredns/enclave"
)

func main() {
	socketPath := flag.String("socket", "/tmp/codoh-enclave.sock", "Unix socket path")
	secretFile := flag.String("secret", "", "Path to master secret file (hex-encoded, for simulation mode)")
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

		// Load cache config from environment
		cfg := enclave.DefaultConfig()
		loadOptionalEnvSettings(cfg)

		// Create simple LRU cache (no stochastic defenses for CODoH-base)
		cache := enclave.NewLRUCache(cfg.CacheSize)
		log.Printf("Proxy mode: LRU cache capacity=%d", cfg.CacheSize)

		server := NewProxyServer(keypair, cache, *targetURL, *tlsCert, *tlsKey, *httpsPort)

		// Handle shutdown
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

	// Load optional settings from environment (master secret already provisioned)
	loadOptionalEnvSettings(cfg)

	// Initialize epoch manager for token verification
	epochMgr, err := enclave.NewEpochManager(cfg.MasterSecret, cfg.EpochDuration)
	if err != nil {
		log.Fatalf("Failed to create epoch manager: %v", err)
	}
	log.Printf("Epoch manager initialized, current epoch: %d", epochMgr.CurrentEpoch())

	// Initialize spent set
	spentSet := enclave.NewSpentSet(epochMgr.CurrentEpoch())

	// Build stochastic config
	stochasticCfg := enclave.StochasticConfig{
		HitSuppressionProb: cfg.HitSuppressionProb,
		InsertProb:         cfg.InsertProb,
		ChurnInterval:      cfg.ChurnInterval,
		ChurnEnabled:       cfg.ChurnEnabled,
	}

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
		oramCache, err = enclave.NewORAMCacheWithStochastic(oramCfg, stochasticCfg)
		if err != nil {
			log.Fatalf("Failed to create ORAM cache: %v", err)
		}
		cache = oramCache
		log.Printf("ORAM cache: capacity=%d, p_fn=%.2f, p_ins=%.2f, churn=%v",
			cfg.CacheSize, stochasticCfg.HitSuppressionProb, stochasticCfg.InsertProb,
			stochasticCfg.ChurnEnabled)
	} else {
		cache = enclave.NewLRUCacheWithStochastic(cfg.CacheSize, stochasticCfg)
		log.Printf("LRU cache: capacity=%d, p_fn=%.2f, p_ins=%.2f, churn=%v",
			cfg.CacheSize, stochasticCfg.HitSuppressionProb, stochasticCfg.InsertProb,
			stochasticCfg.ChurnEnabled)
	}

	// Remove stale socket
	os.Remove(cfg.SocketPath)

	// Initialize MLE cache (always uses ORAM)
	mleCacheCfg := enclave.ORAMCacheConfig{
		Capacity:     cfg.CacheSize,
		BlockSize:    cfg.ORAMBlockSize,
		BucketSize:   5,
		ConstantTime: true,
	}
	mleCache, err := enclave.NewMLECacheWithStochastic(mleCacheCfg, stochasticCfg)
	if err != nil {
		log.Fatalf("Failed to create MLE cache: %v", err)
	}
	log.Printf("MLE cache initialized: capacity=%d, block_size=%d", cfg.CacheSize, cfg.ORAMBlockSize)

	// Create handler
	handler := &EnclaveHandler{
		keypair:             keypair,
		epochMgr:            epochMgr,
		spentSet:            spentSet,
		cache:               cache,
		oramCache:           oramCache,
		mleCache:            mleCache,
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

// loadOptionalEnvSettings loads optional settings from environment variables.
// Does not require CODOH_MASTER_SECRET since it's already provisioned.
func loadOptionalEnvSettings(cfg *enclave.Config) {
	if dur := os.Getenv("CODOH_EPOCH_DURATION"); dur != "" {
		if secs, err := strconv.Atoi(dur); err == nil {
			cfg.EpochDuration = time.Duration(secs) * time.Second
		}
	}
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
	if p := os.Getenv("CODOH_HIT_SUPPRESSION_PROB"); p != "" {
		if prob, err := strconv.ParseFloat(p, 64); err == nil && prob >= 0.0 && prob <= 1.0 {
			cfg.HitSuppressionProb = prob
		}
	}
	if p := os.Getenv("CODOH_INSERT_PROB"); p != "" {
		if prob, err := strconv.ParseFloat(p, 64); err == nil && prob >= 0.0 && prob <= 1.0 {
			cfg.InsertProb = prob
		}
	}
	if interval := os.Getenv("CODOH_CHURN_INTERVAL_SECS"); interval != "" {
		if secs, err := strconv.Atoi(interval); err == nil {
			cfg.ChurnInterval = time.Duration(secs) * time.Second
		}
	}
	if churn := os.Getenv("CODOH_CHURN_ENABLED"); churn == "true" || churn == "1" {
		cfg.ChurnEnabled = true
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
	mleCache            *enclave.MLECache  // MLE cache for ciphertext-only storage
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

// HandleMLELookup handles MLE cache lookup requests.
// 1. Decrypt MLEBlobB
// 2. Verify epoch (E or E-1)
// 3. Verify token FIRST
// 4. Check spent set
// 5. Lookup by tag
// 6. If hit: WrapMLEResponse(Kc, exp, ciphertext)
func (h *EnclaveHandler) HandleMLELookup(blobB, clientIP string) *enclave.Response {
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

	// Decrypt and parse MLEBlobB
	blob, err := h.keypair.DecryptMLEBlobB(blobBytes)
	if err != nil {
		log.Printf("MLE decrypt failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrDecryptFailed,
		}
	}

	log.Printf("MLE lookup: epoch=%d tag=%x client=%s", blob.Epoch, blob.Tag[:8], clientIP)

	// Verify epoch (current or previous for grace period)
	currentEpoch := h.epochMgr.CurrentEpoch()
	if blob.Epoch != currentEpoch && blob.Epoch != currentEpoch-1 {
		log.Printf("MLE token expired: token epoch %d not in [%d, %d]",
			blob.Epoch, currentEpoch-1, currentEpoch)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrTokenExpired,
		}
	}

	// Verify token FIRST (before any cache operation)
	if !h.epochMgr.Verify(blob.Epoch, blob.TokenInput, blob.TokenOutput) {
		log.Printf("MLE token verification failed")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidToken,
		}
	}

	// Check spent set
	tokenID := append(blob.TokenInput, blob.TokenOutput...)
	if !h.spentSet.MarkSpent(tokenID) {
		log.Printf("MLE token already spent")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrTokenSpent,
		}
	}

	log.Printf("MLE token verified and marked spent, spent set size: %d", h.spentSet.Size())

	// Lookup by tag in MLE cache
	entry, ok := h.mleCache.Get(blob.Tag)
	if !ok {
		// Cache miss
		h.logMLECacheOp("miss", blob.Tag)
		return &enclave.Response{
			Status: enclave.StatusMiss,
			Kc:     base64.StdEncoding.EncodeToString(blob.Kc),
		}
	}

	// Cache hit - wrap response under client's Kc
	wrapped, err := enclave.WrapMLEResponse(blob.Kc, entry.Exp, entry.Ciphertext)
	if err != nil {
		log.Printf("MLE wrap failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInternal,
		}
	}

	h.logMLECacheOp("hit", blob.Tag)
	return &enclave.Response{
		Status:   enclave.StatusHit,
		Response: base64.StdEncoding.EncodeToString(wrapped),
		Exp:      entry.Exp,
	}
}

// HandleMLEStore handles MLE cache store requests from target.
// 1. Decrypt MLEInsertBlob
// 2. Verify signature: Sign_T(epoch || tag || exp || SHA256(C))
// 3. Check expiry not in past
// 4. Store in MLECache
func (h *EnclaveHandler) HandleMLEStore(mleInsertBlob string) *enclave.Response {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(mleInsertBlob)
	if err != nil {
		log.Printf("MLE store: invalid base64 encoding")
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  "invalid_encoding",
		}
	}

	// Decrypt and parse MLEInsertBlob
	blob, err := h.keypair.DecryptMLEInsertBlob(ciphertext)
	if err != nil {
		log.Printf("MLE store: decrypt failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrDecryptFailed,
		}
	}

	log.Printf("MLE store: epoch=%d tag=%x exp=%d ctLen=%d",
		blob.Epoch, blob.Tag[:8], blob.Exp, len(blob.Ciphertext))

	// Verify signature if signing key is configured
	if len(h.targetSigningPubKey) > 0 {
		// Compute signature input
		toVerify := enclave.ComputeMLESignatureInput(blob.Epoch, blob.Tag, blob.Exp, blob.Ciphertext)

		if !ed25519.Verify(h.targetSigningPubKey, toVerify, blob.Signature) {
			log.Printf("MLE store: signature verification failed")
			return &enclave.Response{
				Status: enclave.StatusError,
				Error:  enclave.ErrInvalidSignature,
			}
		}
		log.Printf("MLE store: signature verified")
	}

	// Check expiry not in past
	if blob.Exp <= time.Now().Unix() {
		log.Printf("MLE store: entry already expired (exp=%d, now=%d)", blob.Exp, time.Now().Unix())
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrEntryExpired,
		}
	}

	// Store in MLE cache
	entry := &enclave.MLECacheEntry{
		Tag:        blob.Tag,
		Exp:        blob.Exp,
		Ciphertext: blob.Ciphertext,
	}
	h.mleCache.Put(entry)

	h.logMLECacheOp("store", blob.Tag)
	return &enclave.Response{Status: enclave.StatusOK}
}

// logMLECacheOp logs MLE cache operations with stash size.
func (h *EnclaveHandler) logMLECacheOp(op string, tag [16]byte) {
	log.Printf("MLE cache %s for tag=%x, cache_size=%d, stash_size=%d",
		op, tag[:8], h.mleCache.Size(), h.mleCache.StashSize())
}
