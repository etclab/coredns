// Package codohproxy implements the CODoH proxy/relay.
// It fans out Q_E to the enclave and Q_T to the target in parallel,
// then streams tagged chunks: [1B type][2B len][data]...
// Chunks arrive in whichever order the enclave/target responds first.
package codohproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coredns/coredns/enclave"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
)

var log = clog.NewWithPlugin("codohproxy")

const odohContentType = "application/oblivious-dns-message"
const codohResponseContentType = "application/codoh-response"

// Tagged chunk types for codoh-response wire format: [1B type][2B BE len][data]
const (
	ChunkTypeEnclave byte = 1 // Enclave blob (cache hit or dummy)
	ChunkTypeTarget  byte = 2 // ODoH target response
)

type odohProxy struct {
	targetURL          string // https://target:8443/dns-query
	addr               string // :8080
	tlsCert            string
	tlsKey             string
	insecureSkipVerify bool

	// Enclave configuration
	enclaveEnabled      bool
	enclaveSocketPath   string
	enclaveBypassOnFail bool
	enclaveClient       *EnclaveClient

	client  *http.Client
	ln      net.Listener
	mux     *http.ServeMux
	srv     *http.Server
	lnSetup bool
	stop    context.CancelFunc

	// Cached enclave public key (raw bytes, avoids IPC round-trip per request)
	pubKeyMu     sync.RWMutex
	cachedPubKey []byte
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
		// Probe health to set initial healthy status
		if err := p.enclaveClient.CheckHealth(); err != nil {
			if p.enclaveBypassOnFail {
				log.Warningf("Enclave not reachable (bypass enabled): %v", err)
			} else {
				return fmt.Errorf("enclave not reachable: %w", err)
			}
		} else {
			log.Infof("Enclave reachable at %s", p.enclaveSocketPath)
			// Pre-fetch and cache the enclave public key
			if pk, err := p.enclaveClient.GetPublicKey(); err == nil && len(pk) > 0 {
				p.cachedPubKey = pk
				log.Infof("Cached enclave public key (%d bytes)", len(pk))
			}
		}
	}

	// Setup HTTP routes
	p.mux = http.NewServeMux()
	p.mux.HandleFunc("/proxy", p.proxyHandler)
	p.mux.HandleFunc("/health", p.healthHandler)
	if p.enclaveEnabled {
		p.mux.HandleFunc("/enclave-keys", p.enclaveKeysHandler)
		p.mux.HandleFunc("/cache-insert", p.cacheInsertHandler)
		log.Infof("Registered /enclave-keys and /cache-insert endpoints")
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

	log.Infof("CODoH proxy listening on %s, target: %s", p.addr, p.targetURL)
	return nil
}

func (p *odohProxy) OnFinalShutdown() error {
	if !p.lnSetup {
		return nil
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

func (p *odohProxy) proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

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

	// Read Q_E from header (base64-encoded)
	qeHeader := r.Header.Get("X-CoDOH-Query")

	// If no Q_E or enclave not available, degrade to standard ODoH relay
	if qeHeader == "" || !p.enclaveEnabled || p.enclaveClient == nil || !p.enclaveClient.IsHealthy() {
		p.forwardToTarget(w, r, start)
		return
	}

	// Read Q_T from body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	// Build target URL
	targetURL := p.resolveTargetURL(r)

	// Parallel fan-out: goroutine A → enclave, goroutine B → target
	type enclaveResult struct {
		resp *enclaveResponse
		err  error
		dur  time.Duration
	}
	type targetResult struct {
		resp *http.Response
		body []byte
		err  error
		dur  time.Duration
	}

	// Decode Q_E from base64 header to raw bytes for binary IPC
	qeBytes, err := base64.StdEncoding.DecodeString(qeHeader)
	if err != nil {
		http.Error(w, "Invalid Q_E encoding", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	enclaveCh := make(chan enclaveResult, 1)
	targetCh := make(chan targetResult, 1)

	// Goroutine A: send Q_E to enclave (~1ms)
	go func() {
		t0 := time.Now()
		resp, err := p.enclaveClient.ProcessQE(qeBytes)
		enclaveCh <- enclaveResult{resp, err, time.Since(t0)}
	}()

	// Goroutine B: forward Q_T to target (~25ms)
	go func() {
		t0 := time.Now()
		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			targetCh <- targetResult{err: err, dur: time.Since(t0)}
			return
		}
		req.Header.Set("Content-Type", odohContentType)

		// Include cached enclave public key for cache-insert encryption
		p.pubKeyMu.RLock()
		pk := p.cachedPubKey
		p.pubKeyMu.RUnlock()
		if len(pk) > 0 {
			req.Header.Set("X-Enclave-PubKey", base64.StdEncoding.EncodeToString(pk))
		}

		resp, err := p.client.Do(req)
		if err != nil {
			targetCh <- targetResult{err: err, dur: time.Since(t0)}
			return
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		targetCh <- targetResult{resp: resp, body: respBody, err: err, dur: time.Since(t0)}
	}()

	// Race: write whichever chunk arrives first so the client can process
	// it immediately. On a miss (target-first), latency ≈ ODoH.
	// On a hit (enclave-first), latency ≈ enclave IPC.
	flusher, _ := w.(http.Flusher)

	// processEnclave extracts the blob or error from the enclave result.
	processEnclave := func(res enclaveResult) ([]byte, string) {
		if res.err != nil {
			log.Errorf("Enclave IPC error: %v", res.err)
			go p.refreshEnclavePubKey()
			return nil, "enclave_unavailable"
		}
		switch res.resp.Status {
		case enclave.BinStatusKeyRotated:
			log.Infof("Enclave key rotation detected")
			go p.refreshEnclavePubKey()
			return nil, "key_rotated"
		case enclave.BinStatusError:
			return nil, string(res.resp.Payload)
		default:
			return res.resp.Payload, ""
		}
	}

	var durEnclaveIPC, durTargetHTTP time.Duration
	var firstChunk time.Duration

	select {
	case encRes := <-enclaveCh:
		durEnclaveIPC = encRes.dur
		enclaveBlob, enclaveError := processEnclave(encRes)
		if enclaveError != "" {
			// Enclave failed first — wait for target, degrade to ODoH.
			targetRes := <-targetCh
			durTargetHTTP = targetRes.dur
			if targetRes.err != nil {
				http.Error(w, "Target request failed", http.StatusBadGateway)
				proxyRequestsTotal.WithLabelValues("error").Inc()
				return
			}
			w.Header().Set("Content-Type", odohContentType)
			w.Header().Set("X-CoDOH-Enclave-Error", enclaveError)
			if enclaveError == "key_rotated" {
				w.Header().Set("X-CoDOH-Key-Rotated", "true")
			}
			firstChunk = time.Since(start)
			w.WriteHeader(http.StatusOK)
			w.Write(targetRes.body)
			proxyRequestsTotal.WithLabelValues("degraded").Inc()
		} else {
			// Enclave arrived first — write enclave chunk, then target.
			w.Header().Set("Content-Type", codohResponseContentType)
			firstChunk = time.Since(start)
			w.WriteHeader(http.StatusOK)
			writeTaggedChunk(w, ChunkTypeEnclave, enclaveBlob)
			if flusher != nil {
				flusher.Flush()
			}

			targetRes := <-targetCh
			durTargetHTTP = targetRes.dur
			if targetRes.err != nil {
				log.Errorf("Target failed (enclave chunk already sent): %v", targetRes.err)
			} else {
				writeTaggedChunk(w, ChunkTypeTarget, targetRes.body)
			}
			proxyRequestsTotal.WithLabelValues("enclave_ok").Inc()
		}

	case targetRes := <-targetCh:
		durTargetHTTP = targetRes.dur
		if targetRes.err != nil {
			// Target failed first — wait for enclave, try to salvage.
			encRes := <-enclaveCh
			durEnclaveIPC = encRes.dur
			enclaveBlob, enclaveError := processEnclave(encRes)
			if enclaveError != "" || len(enclaveBlob) == 0 {
				http.Error(w, "Target request failed", http.StatusBadGateway)
				proxyRequestsTotal.WithLabelValues("error").Inc()
				return
			}
			// Write enclave-only response (client uses it on hit, fails on miss)
			w.Header().Set("Content-Type", codohResponseContentType)
			firstChunk = time.Since(start)
			w.WriteHeader(http.StatusOK)
			writeTaggedChunk(w, ChunkTypeEnclave, enclaveBlob)
			proxyRequestsTotal.WithLabelValues("enclave_ok").Inc()
		} else {
			// Target arrived first — write target chunk, then enclave.
			w.Header().Set("Content-Type", codohResponseContentType)
			firstChunk = time.Since(start)
			w.WriteHeader(http.StatusOK)
			writeTaggedChunk(w, ChunkTypeTarget, targetRes.body)
			if flusher != nil {
				flusher.Flush()
			}

			encRes := <-enclaveCh
			durEnclaveIPC = encRes.dur
			enclaveBlob, enclaveError := processEnclave(encRes)
			if enclaveError == "" && len(enclaveBlob) > 0 {
				writeTaggedChunk(w, ChunkTypeEnclave, enclaveBlob)
			}
			// If enclave failed, client only has target chunk — still valid on miss.
			proxyRequestsTotal.WithLabelValues("enclave_ok").Inc()
		}
	}

	total := time.Since(start)
	log.Infof("[proxy-timing] enclave_ipc=%dµs target_http=%dµs first_chunk=%dµs total=%dµs",
		durEnclaveIPC.Microseconds(), durTargetHTTP.Microseconds(),
		firstChunk.Microseconds(), total.Microseconds())
	proxyLatencySeconds.Observe(total.Seconds())
}

// forwardToTarget forwards the request directly to the target (standard ODoH relay).
func (p *odohProxy) forwardToTarget(w http.ResponseWriter, r *http.Request, start time.Time) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	targetURL := p.resolveTargetURL(r)

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

	p.pubKeyMu.RLock()
	pk := p.cachedPubKey
	p.pubKeyMu.RUnlock()

	if len(pk) == 0 {
		// Cache empty — fetch and cache
		var err error
		pk, err = p.enclaveClient.GetPublicKey()
		if err != nil {
			log.Errorf("Failed to get enclave public key: %v", err)
			http.Error(w, "Failed to get public key", http.StatusInternalServerError)
			return
		}
		p.pubKeyMu.Lock()
		p.cachedPubKey = pk
		p.pubKeyMu.Unlock()
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, base64.StdEncoding.EncodeToString(pk))
}

// cacheInsertPayload is the JSON body received from the target's POST /cache-insert.
type cacheInsertPayload struct {
	EncryptedBlob string `json:"encrypted_blob"`
	Signature     string `json:"signature"`
}

// cacheInsertHandler receives cache-insert bundles from the target and forwards
// them to the enclave via store_encrypted IPC.
func (p *odohProxy) cacheInsertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var payload cacheInsertPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.EncryptedBlob == "" {
		http.Error(w, "Missing encrypted_blob", http.StatusBadRequest)
		return
	}

	if p.enclaveClient == nil {
		http.Error(w, "Enclave not configured", http.StatusBadGateway)
		return
	}

	blobBytes, err := base64.StdEncoding.DecodeString(payload.EncryptedBlob)
	if err != nil {
		http.Error(w, "Invalid blob encoding", http.StatusBadRequest)
		return
	}
	var sigBytes []byte
	if payload.Signature != "" {
		sigBytes, err = base64.StdEncoding.DecodeString(payload.Signature)
		if err != nil {
			http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
			return
		}
	}

	if err := p.enclaveClient.StoreCacheInsert(blobBytes, sigBytes); err != nil {
		log.Errorf("Cache-insert IPC failed: %v", err)
		http.Error(w, "Enclave IPC failed", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// resolveTargetURL builds the target URL from query parameters or default.
func (p *odohProxy) resolveTargetURL(r *http.Request) string {
	if targetHost := r.URL.Query().Get("targethost"); targetHost != "" {
		targetPath := r.URL.Query().Get("targetpath")
		if targetPath == "" {
			targetPath = "/dns-query"
		}
		return "https://" + targetHost + targetPath
	}
	return p.targetURL
}

// writeTaggedChunk writes [1B type][2B BE len][data] to w.
func writeTaggedChunk(w http.ResponseWriter, chunkType byte, data []byte) {
	var hdr [3]byte
	hdr[0] = chunkType
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(data)))
	w.Write(hdr[:])
	w.Write(data)
}

// refreshEnclavePubKey re-fetches the enclave public key and updates the cache.
func (p *odohProxy) refreshEnclavePubKey() {
	pk, err := p.enclaveClient.GetPublicKey()
	if err != nil {
		log.Errorf("pk_E refresh failed: %v", err)
		return
	}
	p.pubKeyMu.Lock()
	p.cachedPubKey = pk
	p.pubKeyMu.Unlock()
	log.Infof("Refreshed cached enclave public key (%d bytes)", len(pk))
}
