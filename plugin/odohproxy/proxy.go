// Package odohproxy implements a stateless ODoH proxy/relay per RFC 9230.
package odohproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
)

var log = clog.NewWithPlugin("odohproxy")

const odohContentType = "application/oblivious-dns-message"

type odohProxy struct {
	targetURL          string // https://target:8443/dns-query
	addr               string // :8080
	tlsCert            string
	tlsKey             string
	insecureSkipVerify bool

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

	// Setup HTTP routes (consistent with Cloudflare odoh-client-go)
	p.mux = http.NewServeMux()
	p.mux.HandleFunc("/proxy", p.proxyHandler)
	p.mux.HandleFunc("/health", p.healthHandler)

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

	// Read encrypted query (pass through, don't inspect)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		proxyRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	// Build target URL from query params (odoh-client-go style) or use configured target
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

	// Relay response back to client
	w.Header().Set("Content-Type", odohContentType)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	proxyRequestsTotal.WithLabelValues("success").Inc()
	proxyLatencySeconds.Observe(time.Since(start).Seconds())
}