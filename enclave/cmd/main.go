// CODoH Enclave - SGX enclave for cache lookup and response encryption.
// Build with EGo: ego-go build -o enclave ./enclave/cmd
// Dev build: go build -o enclave-sim ./enclave/cmd
package main

import (
	"crypto/ed25519"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
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
		replayDelta:         cfg.ReplayDelta,
		// tLatest zero-initialized by atomic.Int64 default
		defensiveMode:      true, // always start in defensive mode (warm-up)
		outstandingQueries: make(map[string]int64),
		warmupThreshold:    cfg.WarmupThreshold,
		omissionThreshold:  cfg.OmissionThreshold,
		outstandingTTLSecs: cfg.OutstandingTTLSecs,
		startedAt:          time.Now().Format(time.RFC3339),
		insertionQueue:     enclave.NewInsertionQueue(cfg.QueueMaxSize),
		batchSize:          cfg.BatchSize,
		batchCommitProb:    cfg.BatchCommitProb,
	}
	log.Printf("Defensive mode: ACTIVE (warmup threshold=%d)", cfg.WarmupThreshold)
	log.Printf("Batch config: size=%d, commit_prob=%.2f, queue_max=%d",
		cfg.BatchSize, cfg.BatchCommitProb, cfg.QueueMaxSize)
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
	if delta := os.Getenv("CODOH_REPLAY_DELTA_SECS"); delta != "" {
		if f, err := strconv.ParseFloat(delta, 64); err == nil && f >= 0 {
			cfg.ReplayDelta = f
		}
	}
	if threshold := os.Getenv("CODOH_WARMUP_THRESHOLD"); threshold != "" {
		if n, err := strconv.Atoi(threshold); err == nil && n > 0 {
			cfg.WarmupThreshold = n
		}
	}
	if threshold := os.Getenv("CODOH_OMISSION_THRESHOLD"); threshold != "" {
		if n, err := strconv.Atoi(threshold); err == nil && n > 0 {
			cfg.OmissionThreshold = n
		}
	}
	if ttl := os.Getenv("CODOH_OUTSTANDING_TTL_SECS"); ttl != "" {
		if n, err := strconv.Atoi(ttl); err == nil && n > 0 {
			cfg.OutstandingTTLSecs = n
		}
	}
	if bs := os.Getenv("CODOH_BATCH_SIZE"); bs != "" {
		if n, err := strconv.Atoi(bs); err == nil && n > 0 {
			cfg.BatchSize = n
		}
	}
	if prob := os.Getenv("CODOH_BATCH_COMMIT_PROB"); prob != "" {
		if f, err := strconv.ParseFloat(prob, 64); err == nil && f > 0 && f <= 1 {
			cfg.BatchCommitProb = f
		}
	}
	if qs := os.Getenv("CODOH_QUEUE_MAX_SIZE"); qs != "" {
		if n, err := strconv.Atoi(qs); err == nil && n > 0 {
			cfg.QueueMaxSize = n
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
	oramCache           *enclave.ORAMCache // nil if not using ORAM (for stash monitoring)
	targetSigningPubKey ed25519.PublicKey   // Target's Ed25519 public key
	defaultPadSize      int
	tLatest             atomic.Int64 // monotonic logical clock (unix seconds)
	replayDelta         float64      // δ in seconds

	// Defensive mode (Sprint 3)
	mu                 sync.Mutex
	defensiveMode      bool             // true on boot + on omission detection
	outstandingQueries map[string]int64 // canonical_query -> tLatest at time of miss
	warmupThreshold    int              // cache entries needed to exit defensive mode
	omissionThreshold  int              // outstanding queries to trigger defensive mode
	outstandingTTLSecs int              // logical-time window in seconds for outstanding entry eviction
	startedAt          string           // RFC3339 timestamp of handler construction

	// Batched cache updates (Sprint 4)
	insertionQueue        *enclave.InsertionQueue
	batchSize             int
	batchCommitProb       float64
	totalCommits          atomic.Int64
	totalEntriesCommitted atomic.Int64
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
	// Key rotation takes priority: if HPKE decryption fails (wrong key or corrupted),
	// return key_rotated so the client re-attests.
	query, kr, err := h.keypair.DecryptQueryE(qeBytes)
	if err != nil {
		log.Printf("DecryptQueryE failed (key rotation?): %v", err)
		return &enclave.Response{
			Status: enclave.StatusKeyRotated,
		}
	}

	h.mu.Lock()
	inDefensiveMode := h.defensiveMode
	h.mu.Unlock()

	var resp *enclave.Response

	// Defensive mode: decrypt succeeded (needed for protocol), but return dummy.
	// Indistinguishable from a normal cache miss to the proxy.
	if inDefensiveMode {
		_ = kr // kr derived but not used — defensive mode returns dummy
		dummy := enclave.GenerateDummyResponse(h.defaultPadSize)
		h.logCacheOp("miss(defensive)", string(query))
		resp = &enclave.Response{
			Status:   enclave.StatusMiss,
			Response: base64.StdEncoding.EncodeToString(dummy),
		}
	} else {
		canonicalQuery := string(query)

		// Cache lookup with logical time
		tLatest := h.tLatest.Load()
		if cachedResp, ok := h.cache.Get(canonicalQuery, tLatest); ok {
			// Cache hit — encrypt under session key k_r
			encrypted, encErr := enclave.EncryptCachedResponse(kr, cachedResp)
			if encErr != nil {
				log.Printf("EncryptCachedResponse failed: %v", encErr)
				// Fall through to dummy
			} else {
				h.logCacheOp("hit", canonicalQuery)
				resp = &enclave.Response{
					Status:   enclave.StatusHit,
					Response: base64.StdEncoding.EncodeToString(encrypted),
				}
			}
		}

		if resp == nil {
			// Cache miss — track outstanding query for omission detection
			h.mu.Lock()
			if _, exists := h.outstandingQueries[canonicalQuery]; !exists {
				h.outstandingQueries[canonicalQuery] = h.tLatest.Load()
			}
			if len(h.outstandingQueries) > h.omissionThreshold {
				log.Printf("Omission threshold exceeded (%d > %d) — entering defensive mode",
					len(h.outstandingQueries), h.omissionThreshold)
				h.cache.Clear()
				h.outstandingQueries = make(map[string]int64)
				h.defensiveMode = true
			}
			h.mu.Unlock()

			// Return dummy (indistinguishable from hit)
			dummy := enclave.GenerateDummyResponse(h.defaultPadSize)
			h.logCacheOp("miss", canonicalQuery)
			resp = &enclave.Response{
				Status:   enclave.StatusMiss,
				Response: base64.StdEncoding.EncodeToString(dummy),
			}
		}
	}

	// Pseudorandom batch commit (D1: commits only on query path, D7: synchronous)
	if cryptoRandFloat64() < h.batchCommitProb {
		if n := h.insertionQueue.Len(); n > 0 {
			commitSize := h.batchSize
			if commitSize > n {
				commitSize = n
			}
			batch := h.insertionQueue.DrainBatch(commitSize)
			if len(batch) > 0 {
				h.cache.PutBatch(batch)
				h.totalCommits.Add(1)
				h.totalEntriesCommitted.Add(int64(len(batch)))

				// Re-check warm-up threshold after commit
				h.mu.Lock()
				if h.defensiveMode && h.cache.Size() >= h.warmupThreshold {
					h.defensiveMode = false
					log.Printf("[enclave] warm-up complete: cache size %d >= threshold %d",
						h.cache.Size(), h.warmupThreshold)
				}
				h.mu.Unlock()
			}
		}
	}

	return resp
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

	// Parse multi-entry bundle (real + covers)
	entries, err := enclave.ParseMultiBundle(plaintext)
	if err != nil {
		log.Printf("StoreEncrypted: parse multi-bundle failed: %v", err)
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrInvalidBlob,
		}
	}

	enqueued := 0
	for i, entry := range entries {
		// Validate timestamp per-entry (δ-window check + advance t_latest)
		if err := h.validateTimestamp(entry.Timestamp); err != nil {
			log.Printf("StoreEncrypted: entry %d stale timestamp (ts=%d)", i, entry.Timestamp)
			continue // skip stale entry, process rest
		}

		// Enqueue for batched commit
		h.insertionQueue.Enqueue(enclave.PendingInsert{
			Query:      entry.CanonicalQuery,
			Response:   entry.DNSResponse,
			TTL:        entry.TTL,
			InsertedAt: entry.Timestamp,
		})
		h.logCacheOp("enqueue", entry.CanonicalQuery)
		enqueued++

		// Outstanding query tracking: remove if present (no-op for covers)
		h.mu.Lock()
		delete(h.outstandingQueries, entry.CanonicalQuery)
		h.mu.Unlock()
	}

	// Inline cleanup: evict outstanding entries older than TTL window
	h.mu.Lock()
	currentTLatest := h.tLatest.Load()
	ttlWindow := int64(h.outstandingTTLSecs)
	for q, entryT := range h.outstandingQueries {
		if entryT < currentTLatest-ttlWindow {
			delete(h.outstandingQueries, q)
		}
	}
	h.mu.Unlock()

	log.Printf("StoreEncrypted: enqueued %d/%d entries", enqueued, len(entries))

	if enqueued == 0 {
		return &enclave.Response{
			Status: enclave.StatusError,
			Error:  enclave.ErrStaleTimestamp,
		}
	}

	return &enclave.Response{Status: enclave.StatusOK}
}

// validateTimestamp checks the timestamp against the δ-window and advances tLatest.
func (h *EnclaveHandler) validateTimestamp(ts int64) error {
	tLatest := h.tLatest.Load()
	deltaSeconds := int64(h.replayDelta)

	if ts < tLatest-deltaSeconds {
		log.Printf("[REPLAY] rejected stale insert: ts=%d tLatest=%d delta=%v", ts, tLatest, h.replayDelta)
		return fmt.Errorf(enclave.ErrStaleTimestamp)
	}

	// CAS loop: advance tLatest = max(tLatest, ts)
	for {
		old := h.tLatest.Load()
		if ts <= old {
			break
		}
		if h.tLatest.CompareAndSwap(old, ts) {
			break
		}
	}
	return nil
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
	return &enclave.Response{
		Status:                enclave.StatusOK,
		StartedAt:             h.startedAt,
		QueueDepth:            h.insertionQueue.Len(),
		TotalCommits:          h.totalCommits.Load(),
		TotalEntriesCommitted: h.totalEntriesCommitted.Load(),
	}
}

// cryptoRandFloat64 returns a uniform random float64 in [0, 1) using crypto/rand.
func cryptoRandFloat64() float64 {
	var buf [8]byte
	crypto_rand.Read(buf[:])
	return float64(binary.LittleEndian.Uint64(buf[:])>>11) / (1 << 53)
}

// logCacheOp logs cache operations with stash size when using ORAM.
func (h *EnclaveHandler) logCacheOp(op, query string) {
	if h.oramCache != nil {
		log.Printf("Cache %s for %s, cache_size=%d, stash_size=%d", op, query, h.cache.Size(), h.oramCache.StashSize())
	} else {
		log.Printf("Cache %s for %s, cache_size=%d", op, query, h.cache.Size())
	}
}
