// Package codohproxy implements the CODoH proxy/relay.
// It fans out Q_E to the enclave and Q_T to the target in parallel,
// then streams a two-chunk response: [2-byte len][chunk1][chunk2].
package codohproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
)

var log = clog.NewWithPlugin("codohproxy")

const odohContentType = "application/oblivious-dns-message"
const codohResponseContentType = "application/codoh-response"

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
		}
	}

	// Setup HTTP routes
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

	// Read Q_E from header
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
		resp *EnclaveResponse
		err  error
	}
	type targetResult struct {
		resp *http.Response
		body []byte
		err  error
	}

	enclaveCh := make(chan enclaveResult, 1)
	targetCh := make(chan targetResult, 1)

	// Goroutine A: send Q_E to enclave (~1ms)
	go func() {
		resp, err := p.enclaveClient.ProcessQE(qeHeader)
		enclaveCh <- enclaveResult{resp, err}
	}()

	// Goroutine B: forward Q_T to target (~25ms)
	go func() {
		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			targetCh <- targetResult{err: err}
			return
		}
		req.Header.Set("Content-Type", odohContentType)

		// Include enclave public key for cache-insert encryption
		if pk, err := p.enclaveClient.GetPublicKey(); err == nil && pk != "" {
			req.Header.Set("X-Enclave-PubKey", pk)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			targetCh <- targetResult{err: err}
			return
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		targetCh <- targetResult{resp: resp, body: respBody, err: err}
	}()

	// Wait for enclave (fast leg)
	enclaveRes := <-enclaveCh

	var enclaveBlob []byte
	var enclaveError string

	if enclaveRes.err != nil {
		log.Errorf("Enclave IPC error: %v", enclaveRes.err)
		enclaveError = "enclave_unavailable"
		// Reactive pk_E refresh
		go p.refreshEnclavePubKey()
	} else if enclaveRes.resp.Status == statusError && enclaveRes.resp.Error == "hpke_error" {
		enclaveError = "key_mismatch"
		// Reactive pk_E refresh on HPKE error
		go p.refreshEnclavePubKey()
	} else if enclaveRes.resp.Status == statusError {
		enclaveError = enclaveRes.resp.Error
	} else {
		// Decode enclave blob (hit or dummy — opaque to proxy)
		enclaveBlob, err = base64.StdEncoding.DecodeString(enclaveRes.resp.Response)
		if err != nil {
			log.Errorf("Enclave response decode error: %v", err)
			enclaveError = "decode_error"
		}
	}

	// Wait for target (slow leg)
	targetRes := <-targetCh

	if targetRes.err != nil {
		// Target failed. If we have an enclave blob, write it as a single chunk.
		// Client can use cache hit if present; otherwise it's an error.
		if enclaveError == "" && len(enclaveBlob) > 0 {
			// Can't do two-chunk without target response. Degrade.
			log.Errorf("Target request failed (have enclave blob, but no target response): %v", targetRes.err)
		}
		http.Error(w, "Target request failed", http.StatusBadGateway)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Fire-and-forget cache-insert if headers present
	if enclaveCache := targetRes.resp.Header.Get("X-Enclave-Cache"); enclaveCache != "" {
		sig := targetRes.resp.Header.Get("X-Enclave-Cache-Sig")
		go func() {
			if err := p.enclaveClient.StoreCacheInsert(enclaveCache, sig); err != nil {
				log.Errorf("Async cache-insert failed: %v", err)
			}
		}()
	}

	// Write response
	if enclaveError == "" && len(enclaveBlob) > 0 {
		// Two-chunk response: [2-byte len][chunk1 (enclave blob)][chunk2 (ODoH response)]
		w.Header().Set("Content-Type", codohResponseContentType)
		w.WriteHeader(http.StatusOK)

		// Write chunk1 length prefix (big-endian uint16)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(enclaveBlob)))
		w.Write(lenBuf[:])

		// Write chunk1 (enclave blob)
		w.Write(enclaveBlob)

		// Flush so client can start processing chunk1 immediately
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		// Write chunk2 (ODoH response)
		w.Write(targetRes.body)

		if enclaveRes.resp != nil && enclaveRes.resp.Status == statusHit {
			proxyRequestsTotal.WithLabelValues("cache_hit").Inc()
		} else {
			proxyRequestsTotal.WithLabelValues("cache_miss").Inc()
		}
	} else {
		// Degraded: standard ODoH response
		w.Header().Set("Content-Type", odohContentType)
		if enclaveError != "" {
			w.Header().Set("X-CoDOH-Enclave-Error", enclaveError)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(targetRes.body)

		proxyRequestsTotal.WithLabelValues("degraded").Inc()
	}

	proxyLatencySeconds.Observe(time.Since(start).Seconds())
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

	pubKey, err := p.enclaveClient.GetPublicKey()
	if err != nil {
		log.Errorf("Failed to get enclave public key: %v", err)
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, pubKey)
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

// refreshEnclavePubKey re-fetches the enclave public key (reactive refresh on error).
func (p *odohProxy) refreshEnclavePubKey() {
	if _, err := p.enclaveClient.GetPublicKey(); err != nil {
		log.Errorf("pk_E refresh failed: %v", err)
	}
}
