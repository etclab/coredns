// Package codohproxy implements a stateless ODoH proxy/relay per RFC 9230.
package codohproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
)

var log = clog.NewWithPlugin("codohproxy")

const odohContentType = "application/oblivious-dns-message"

type odohProxy struct {
	targetURL          string // https://target:8443/dns-query
	addr               string // :8080
	tlsCert            string
	tlsKey             string
	insecureSkipVerify bool
	verifyURL          string // https://target:8443/verify

	// Enclave configuration
	enclaveEnabled       bool
	enclaveSocketPath    string
	enclaveBypassOnFail  bool
	enclaveClient        *EnclaveClient

	client  *http.Client
	ln      net.Listener
	mux     *http.ServeMux
	srv     *http.Server
	lnSetup bool
	stop    context.CancelFunc
}

func (p *odohProxy) OnStartup() error {
	// Setup HTTP client for target
	tlsClientConfig, err := pkgtls.NewTLSClientConfig("")
	if err != nil {
		return err
	}
	if p.insecureSkipVerify {
		tlsClientConfig.InsecureSkipVerify = true
	}

	transport := pkgtls.NewHTTPSTransport(tlsClientConfig)
	p.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Load TLS config for server
	tlsConfig, err := pkgtls.NewTLSConfig(p.tlsCert, p.tlsKey, "")
	if err != nil {
		return err
	}

	// Create listener
	ln, err := reuseport.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	p.ln = tls.NewListener(ln, tlsConfig)
	p.lnSetup = true

	// Initialize enclave client if enabled
	if p.enclaveEnabled {
		p.enclaveClient = NewEnclaveClient(p.enclaveSocketPath)
		if err := p.enclaveClient.Connect(); err != nil {
			if p.enclaveBypassOnFail {
				log.Warningf("Enclave connection failed (bypass enabled): %v", err)
			} else {
				return fmt.Errorf("enclave connection failed: %w", err)
			}
		} else {
			log.Infof("Connected to enclave at %s", p.enclaveSocketPath)

			// Wait for enclave to be ready (provisioned)
			if err := p.waitForEnclaveReady(30 * time.Second); err != nil {
				if p.enclaveBypassOnFail {
					log.Warningf("Enclave not ready (bypass enabled): %v", err)
				} else {
					return fmt.Errorf("enclave not ready: %w", err)
				}
			}
		}
	}

	// Setup HTTP routes (consistent with Cloudflare odoh-client-go)
	p.mux = http.NewServeMux()
	p.mux.HandleFunc("/proxy", p.proxyHandler)
	p.mux.HandleFunc("/health", p.healthHandler)
	if p.enclaveEnabled {
		p.mux.HandleFunc("/enclave-keys", p.enclaveKeysHandler)
		log.Infof("Registered /enclave-keys endpoint")
	}

	p.srv = &http.Server{
		Handler:      p.mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx := context.Background()
	ctx, p.stop = context.WithCancel(ctx)

	go func() {
		if err := p.srv.Serve(p.ln); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP server error: %v", err)
		}
	}()

	log.Infof("ODoH proxy listening on %s, target: %s", p.addr, p.targetURL)
	return nil
}

func (p *odohProxy) OnFinalShutdown() error {
	if !p.lnSetup {
		return nil
	}

	if p.enclaveClient != nil {
		p.enclaveClient.Close()
	}

	p.stop()
	p.srv.Close()
	p.lnSetup = false
	return nil
}

func (p *odohProxy) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "OK")
}

const codohCachedContentType = "application/codoh-cached"
const codohMLECachedContentType = "application/codoh-mle-cached"

func (p *odohProxy) proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Validate method and content type
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	if r.Header.Get("Content-Type") != odohContentType {
		http.Error(w, "Bad content type", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Enclave-first flow
	if p.enclaveEnabled && p.enclaveClient != nil && p.enclaveClient.IsHealthy() {
		p.handleEnclaveFlow(w, r, start)
		return
	}

	// Bypass mode: Token verification via target
	if p.enclaveEnabled && !p.enclaveBypassOnFail {
		http.Error(w, `{"error":"enclave_unavailable"}`, http.StatusServiceUnavailable)
		proxyRequestsTotal.WithLabelValues("enclave_down").Inc()
		return
	}

	// Token verification fallback
	if p.verifyURL != "" {
		token := r.Header.Get("X-ODoH-Token")
		if token == "" {
			http.Error(w, `{"error":"token_required"}`, http.StatusBadRequest)
			proxyRequestsTotal.WithLabelValues("token_missing").Inc()
			return
		}

		tokenBytes, err := decodeToken(token)
		if err != nil {
			http.Error(w, `{"error":"malformed_token"}`, http.StatusBadRequest)
			proxyRequestsTotal.WithLabelValues("token_invalid").Inc()
			return
		}

		verifyReq, err := http.NewRequest(http.MethodPost, p.verifyURL, bytes.NewReader(tokenBytes))
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			proxyRequestsTotal.WithLabelValues("error").Inc()
			return
		}
		verifyReq.Header.Set("Content-Type", "application/octet-stream")

		verifyResp, err := p.client.Do(verifyReq)
		if err != nil {
			log.Errorf("Token verification request failed: %v", err)
			http.Error(w, `{"error":"verification_failed"}`, http.StatusBadGateway)
			proxyRequestsTotal.WithLabelValues("verify_error").Inc()
			return
		}
		verifyResp.Body.Close()

		if verifyResp.StatusCode != http.StatusOK {
			http.Error(w, `{"error":"token_invalid"}`, http.StatusForbidden)
			proxyRequestsTotal.WithLabelValues("token_rejected").Inc()
			return
		}
	}

	// Forward to target (bypass mode)
	p.forwardToTarget(w, r, start)
}

// handleEnclaveFlow processes requests through the enclave.
func (p *odohProxy) handleEnclaveFlow(w http.ResponseWriter, r *http.Request, start time.Time) {
	// Extract blob B from header
	blobB := r.Header.Get("X-ODoH-Blob")
	if blobB == "" {
		// No blob, fall back to bypass if enabled
		if p.enclaveBypassOnFail {
			log.Debug("No X-ODoH-Blob header, bypassing enclave")
			p.forwardToTarget(w, r, start)
			return
		}
		http.Error(w, `{"error":"blob_required"}`, http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("blob_missing").Inc()
		return
	}

	// Get client IP
	clientIP := getClientIP(r)

	// Check for MLE mode (BlobBv2 uses mle_lookup)
	mleMode := r.Header.Get("X-MLE-Mode") == "true"

	// Send to enclave
	var enclaveResp *EnclaveResponse
	var err error
	if mleMode {
		enclaveResp, err = p.enclaveClient.MLELookup(blobB, clientIP)
	} else {
		enclaveResp, err = p.enclaveClient.ProcessRequest(blobB, clientIP)
	}
	if err != nil {
		log.Errorf("Enclave process error: %v", err)
		if p.enclaveBypassOnFail {
			log.Warning("Enclave error, bypassing to target")
			p.forwardToTarget(w, r, start)
			return
		}
		http.Error(w, `{"error":"enclave_error"}`, http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("enclave_error").Inc()
		return
	}

	switch enclaveResp.Status {
	case statusHit:
		// Cache hit - return encrypted response
		respBytes, err := base64.StdEncoding.DecodeString(enclaveResp.Response)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			proxyRequestsTotal.WithLabelValues("error").Inc()
			return
		}
		contentType := codohCachedContentType
		if mleMode {
			contentType = codohMLECachedContentType
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
		if mleMode {
			proxyRequestsTotal.WithLabelValues("mle_cache_hit").Inc()
		} else {
			proxyRequestsTotal.WithLabelValues("cache_hit").Inc()
		}
		proxyLatencySeconds.Observe(time.Since(start).Seconds())
		return

	case statusMiss:
		// Cache miss - forward to target, then store in cache
		if mleMode {
			p.handleMLECacheMiss(w, r, enclaveResp, start)
		} else {
			p.handleCacheMiss(w, r, enclaveResp, start)
		}
		return

	case statusError:
		// Token error
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, enclaveResp.Error), http.StatusForbidden)
		proxyRequestsTotal.WithLabelValues("token_" + enclaveResp.Error).Inc()
		return

	default:
		http.Error(w, `{"error":"unknown_enclave_status"}`, http.StatusInternalServerError)
		proxyRequestsTotal.WithLabelValues("error").Inc()
	}
}

// handleCacheMiss forwards the request to target and stores the response in cache.
func (p *odohProxy) handleCacheMiss(w http.ResponseWriter, r *http.Request, enclaveResp *EnclaveResponse, start time.Time) {
	// Read ODoH query body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	// Build target URL
	targetURL := p.targetURL
	if targetHost := r.URL.Query().Get("targethost"); targetHost != "" {
		targetPath := r.URL.Query().Get("targetpath")
		if targetPath == "" {
			targetPath = "/dns-query"
		}
		targetURL = "https://" + targetHost + targetPath
	}

	// Forward to target
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	req.Header.Set("Content-Type", odohContentType)

	// Forward blob B to target for signature binding
	if blobB := r.Header.Get("X-ODoH-Blob"); blobB != "" {
		req.Header.Set("X-ODoH-Blob", blobB)
	}

	// Include enclave public key for cache encryption
	var enclavePubKey string
	if p.enclaveClient != nil {
		enclavePubKey, _ = p.enclaveClient.GetPublicKey()
		if enclavePubKey != "" {
			req.Header.Set("X-Enclave-PubKey", enclavePubKey)
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "Target request failed", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer resp.Body.Close()

	// Read target response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read target response", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Store encrypted cache data from target
	if enclaveCache := resp.Header.Get("X-Enclave-Cache"); enclaveCache != "" {
		// Get signature and query from response headers
		sig := resp.Header.Get("X-Enclave-Cache-Sig")
		query := resp.Header.Get("X-Enclave-Cache-Query")
		blobB := r.Header.Get("X-ODoH-Blob")

		// Fall back to enclave's canonical query if target didn't provide one
		if query == "" {
			query = enclaveResp.Query
		}

		// Parse TTL from response header, default to 300
		ttl := 300
		if ttlStr := resp.Header.Get("X-Enclave-Cache-TTL"); ttlStr != "" {
			if parsedTTL, err := strconv.Atoi(ttlStr); err == nil && parsedTTL > 0 {
				ttl = parsedTTL
			}
		}

		// Target encrypted raw DNS under enclave's public key
		go func() {
			if err := p.enclaveClient.StoreEncryptedWithSig(query, enclaveCache, sig, blobB, ttl); err != nil {
				log.Errorf("Failed to store encrypted cache: %v", err)
			}
		}()
	}

	// Relay response back to client
	w.Header().Set("Content-Type", odohContentType)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	proxyRequestsTotal.WithLabelValues("cache_miss").Inc()
	proxyLatencySeconds.Observe(time.Since(start).Seconds())
}

// handleMLECacheMiss forwards the request to target and stores the MLE response in cache.
func (p *odohProxy) handleMLECacheMiss(w http.ResponseWriter, r *http.Request, enclaveResp *EnclaveResponse, start time.Time) {
	// Read ODoH query body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	// Build target URL
	targetURL := p.targetURL
	if targetHost := r.URL.Query().Get("targethost"); targetHost != "" {
		targetPath := r.URL.Query().Get("targetpath")
		if targetPath == "" {
			targetPath = "/dns-query"
		}
		targetURL = "https://" + targetHost + targetPath
	}

	// Forward to target
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	req.Header.Set("Content-Type", odohContentType)

	// Forward blob B to target for signature binding
	if blobB := r.Header.Get("X-ODoH-Blob"); blobB != "" {
		req.Header.Set("X-ODoH-Blob", blobB)
	}

	// Forward MLE mode indicator so target prepares MLE insert blob
	req.Header.Set("X-MLE-Mode", "true")

	// Include enclave public key for MLE cache encryption
	var enclavePubKey string
	if p.enclaveClient != nil {
		enclavePubKey, _ = p.enclaveClient.GetPublicKey()
		if enclavePubKey != "" {
			req.Header.Set("X-Enclave-PubKey", enclavePubKey)
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "Target request failed", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer resp.Body.Close()

	// Read target response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read target response", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Store MLE insert blob from target
	if mleInsertBlob := resp.Header.Get("X-MLE-Insert-Blob"); mleInsertBlob != "" {
		go func() {
			if err := p.enclaveClient.MLEStore(mleInsertBlob); err != nil {
				log.Errorf("Failed to store MLE cache entry: %v", err)
			} else {
				log.Debug("Stored MLE cache entry")
			}
		}()
	}

	// Relay response back to client
	w.Header().Set("Content-Type", odohContentType)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	proxyRequestsTotal.WithLabelValues("mle_cache_miss").Inc()
	proxyLatencySeconds.Observe(time.Since(start).Seconds())
}

// forwardToTarget forwards the request directly to the target (bypass mode).
func (p *odohProxy) forwardToTarget(w http.ResponseWriter, r *http.Request, start time.Time) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	targetURL := p.targetURL
	if targetHost := r.URL.Query().Get("targethost"); targetHost != "" {
		targetPath := r.URL.Query().Get("targetpath")
		if targetPath == "" {
			targetPath = "/dns-query"
		}
		targetURL = "https://" + targetHost + targetPath
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	req.Header.Set("Content-Type", odohContentType)

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "Target request failed", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read target response", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	w.Header().Set("Content-Type", odohContentType)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	proxyRequestsTotal.WithLabelValues("bypass").Inc()
	proxyLatencySeconds.Observe(time.Since(start).Seconds())
}

// enclaveKeysHandler returns the enclave's public key for HPKE encryption.
func (p *odohProxy) enclaveKeysHandler(w http.ResponseWriter, r *http.Request) {
	if p.enclaveClient == nil || !p.enclaveClient.IsHealthy() {
		http.Error(w, "Enclave not available", http.StatusServiceUnavailable)
		return
	}

	pubKey, err := p.enclaveClient.GetPublicKey()
	if err != nil {
		log.Errorf("Failed to get enclave public key: %v", err)
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	// Return base64-encoded public key
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, pubKey)
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := bytes.IndexByte([]byte(xff), ','); idx > 0 {
			return xff[:idx]
		}
		return xff
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// decodeToken decodes a base64-encoded token from the X-ODoH-Token header.
func decodeToken(token string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(token)
}

// waitForEnclaveReady polls the enclave until it reports ready (provisioned).
func (p *odohProxy) waitForEnclaveReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ready, err := p.enclaveClient.CheckReady()
		if err == nil && ready {
			log.Info("Enclave is ready (provisioned)")
			return nil
		}
		if err != nil {
			log.Debugf("Enclave ready check: %v", err)
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("timeout waiting for enclave ready after %v", timeout)
}