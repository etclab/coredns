// proxy_mode.go implements the enclave-proxy HTTPS server for CODoH-base (Config 3).
// Architecture: Client → Enclave-Proxy (HTTPS, with LRU cache) → ODoH Target
// This is the minimal upgrade from ODoH: standard ODoH + enclave-based caching.
// No tokens, no signatures, no IPC — the enclave handles everything directly.
package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/enclave"
)

// ProxyServer is the enclave-proxy HTTPS server for CODoH-base.
type ProxyServer struct {
	keypair   *enclave.EnclaveKeypair
	cache     enclave.Cache
	targetURL string // e.g., "https://127.0.0.1:10444"
	tlsCert   string
	tlsKey    string
	port      int
	client    *http.Client
}

// NewProxyServer creates a new enclave-proxy server.
func NewProxyServer(keypair *enclave.EnclaveKeypair, cache enclave.Cache, targetURL, tlsCert, tlsKey string, port int) *ProxyServer {
	return &ProxyServer{
		keypair:   keypair,
		cache:     cache,
		targetURL: strings.TrimRight(targetURL, "/"),
		tlsCert:   tlsCert,
		tlsKey:    tlsKey,
		port:      port,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Start starts the HTTPS server.
func (s *ProxyServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/enclave-keys", s.handleEnclaveKeys)
	mux.HandleFunc("/proxy", s.handleProxy)
	mux.HandleFunc("/.well-known/odohconfigs", s.handleODoHConfigs)
	mux.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Enclave-proxy starting on %s (target: %s)", addr, s.targetURL)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	return server.ListenAndServeTLS(s.tlsCert, s.tlsKey)
}

// handleEnclaveKeys returns the base64 HPKE public key.
func (s *ProxyServer) handleEnclaveKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pubBytes, err := s.keypair.PublicKeyBytes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(base64.StdEncoding.EncodeToString(pubBytes)))
}

// handleHealth returns OK.
func (s *ProxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("OK"))
}

// handleODoHConfigs proxies the ODoH config request to the target.
func (s *ProxyServer) handleODoHConfigs(w http.ResponseWriter, r *http.Request) {
	targetURL := s.targetURL + "/.well-known/odohconfigs"
	resp, err := s.client.Get(targetURL)
	if err != nil {
		log.Printf("Failed to fetch odohconfigs from target: %v", err)
		http.Error(w, "failed to fetch odohconfigs", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read response", http.StatusBadGateway)
		return
	}

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleProxy is the main request handler.
// Flow:
//  1. Read X-ODoH-Blob header, base64-decode
//  2. Decrypt with enclave private key → plaintext
//  3. Parse simplified blob: kc = plaintext[:32], query = string(plaintext[32:])
//  4. Cache lookup by query
//  5. Hit: encrypt cached response with kc, return as application/codoh-cached
//  6. Miss: forward ODoH body to target, cache the response, return ODoH response
func (s *ProxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read blob header
	blobB64 := r.Header.Get("X-ODoH-Blob")
	if blobB64 == "" {
		http.Error(w, "missing X-ODoH-Blob header", http.StatusBadRequest)
		return
	}

	blobCiphertext, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		http.Error(w, "invalid blob encoding", http.StatusBadRequest)
		return
	}

	// Decrypt blob with enclave private key
	plaintext, err := s.keypair.Decrypt(blobCiphertext)
	if err != nil {
		log.Printf("Blob decrypt failed: %v", err)
		http.Error(w, "blob decrypt failed", http.StatusBadRequest)
		return
	}

	// Parse simplified blob: kc (32) || query (variable)
	kc, query, err := parseSimpleBlobB(plaintext)
	if err != nil {
		log.Printf("Blob parse failed: %v", err)
		http.Error(w, "invalid blob format", http.StatusBadRequest)
		return
	}

	// Cache lookup
	if cachedResp, ok := s.cache.Get(query, 0); ok {
		// Cache hit — encrypt with client's kc and return
		encrypted, err := enclave.EncryptResponse(kc, cachedResp)
		if err != nil {
			log.Printf("Failed to encrypt cached response: %v", err)
			// Fall through to miss path
		} else {
			w.Header().Set("Content-Type", "application/codoh-cached")
			w.Write(encrypted)
			return
		}
	}

	// Cache miss — forward ODoH body to target
	odohBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Forward to target
	targetDNSURL := s.targetURL + "/dns-query"
	targetReq, err := http.NewRequest(http.MethodPost, targetDNSURL, strings.NewReader(string(odohBody)))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	targetReq.Header.Set("Content-Type", "application/oblivious-dns-message")
	targetReq.Header.Set("Accept", "application/oblivious-dns-message")

	// Send enclave public key so target can encrypt cache entry for us
	pubBytes, _ := s.keypair.PublicKeyBytes()
	targetReq.Header.Set("X-Enclave-PubKey", base64.StdEncoding.EncodeToString(pubBytes))

	targetResp, err := s.client.Do(targetReq)
	if err != nil {
		log.Printf("Target request failed: %v", err)
		http.Error(w, "target request failed", http.StatusBadGateway)
		return
	}
	defer targetResp.Body.Close()

	targetBody, err := io.ReadAll(targetResp.Body)
	if err != nil {
		http.Error(w, "failed to read target response", http.StatusBadGateway)
		return
	}

	if targetResp.StatusCode != http.StatusOK {
		log.Printf("Target returned status %d: %s", targetResp.StatusCode, string(targetBody))
		w.WriteHeader(targetResp.StatusCode)
		w.Write(targetBody)
		return
	}

	// Check for encrypted cache entry from target
	encCacheB64 := targetResp.Header.Get("X-Enclave-Cache")
	if encCacheB64 != "" {
		s.storeCacheEntry(query, encCacheB64, targetResp.Header.Get("X-Enclave-Cache-TTL"))
	}

	// Return ODoH response to client
	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.Write(targetBody)
}

// storeCacheEntry decrypts and stores a cache entry from the target.
func (s *ProxyServer) storeCacheEntry(query, encCacheB64, ttlStr string) {
	ciphertext, err := base64.StdEncoding.DecodeString(encCacheB64)
	if err != nil {
		log.Printf("Failed to decode cache entry: %v", err)
		return
	}

	plaintext, err := s.keypair.Decrypt(ciphertext)
	if err != nil {
		log.Printf("Failed to decrypt cache entry: %v", err)
		return
	}

	ttlSecs := uint32(300) // default 5 minutes
	if ttlStr != "" {
		if secs, err := strconv.Atoi(ttlStr); err == nil && secs > 0 {
			ttlSecs = uint32(secs)
		}
	}

	insertedAt := time.Now().Unix()
	s.cache.Put(query, plaintext, insertedAt, ttlSecs)
	log.Printf("Cached response for %s (TTL: %ds, cache_size: %d)", query, ttlSecs, s.cache.Size())
}

// parseSimpleBlobB parses a simplified blob for CODoH-base.
// Format: kc (32 bytes) || canonical_query (variable, e.g., "example.com.:1")
func parseSimpleBlobB(plaintext []byte) (kc []byte, query string, err error) {
	if len(plaintext) < 33 { // 32 bytes kc + at least 1 byte query
		return nil, "", fmt.Errorf("simplified blob too short: %d bytes", len(plaintext))
	}

	kc = make([]byte, 32)
	copy(kc, plaintext[:32])
	query = string(plaintext[32:])

	if query == "" {
		return nil, "", fmt.Errorf("empty query in simplified blob")
	}

	return kc, query, nil
}
