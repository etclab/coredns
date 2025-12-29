// Package odohtarget implements an ODoH target server per RFC 9230.
package odohtarget

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("odohtarget")

const odohContentType = "application/oblivious-dns-message"

type odohTarget struct {
	addr       string // :8443
	tlsCert    string
	tlsKey     string
	upstream   string // 8.8.8.8:53
	logQueries bool

	keyPair   odoh.ObliviousDoHKeyPair
	dnsClient *dns.Client

	ln      net.Listener
	mux     *http.ServeMux
	srv     *http.Server
	lnSetup bool
	stop    context.CancelFunc
}

func (t *odohTarget) OnStartup() error {
	// Generate HPKE keypair
	keyPair, err := odoh.CreateDefaultKeyPair()
	if err != nil {
		return err
	}
	t.keyPair = keyPair
	log.Info("Generated HPKE keypair")

	// Initialize DNS client for upstream
	t.dnsClient = &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Load TLS config
	tlsConfig, err := pkgtls.NewTLSConfig(t.tlsCert, t.tlsKey, "")
	if err != nil {
		return err
	}

	// Create listener
	ln, err := reuseport.Listen("tcp", t.addr)
	if err != nil {
		return err
	}
	t.ln = tls.NewListener(ln, tlsConfig)
	t.lnSetup = true

	// Setup HTTP routes
	t.mux = http.NewServeMux()
	t.mux.HandleFunc("/.well-known/odohconfigs", t.configHandler)
	t.mux.HandleFunc("/dns-query", t.odohQueryHandler)
	t.mux.HandleFunc("/health", t.healthHandler)

	t.srv = &http.Server{
		Handler:      t.mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx := context.Background()
	ctx, t.stop = context.WithCancel(ctx)

	go func() {
		if err := t.srv.Serve(t.ln); err != nil && err != http.ErrServerClosed {
			log.Errorf("HTTP server error: %v", err)
		}
	}()

	log.Infof("ODoH target listening on %s", t.addr)
	return nil
}

func (t *odohTarget) OnFinalShutdown() error {
	if !t.lnSetup {
		return nil
	}

	t.stop()
	t.srv.Close()
	t.lnSetup = false
	return nil
}

func (t *odohTarget) configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{t.keyPair.Config})
	w.Header().Set("Content-Type", odohContentType)
	w.Write(configs.Marshal())
}

func (t *odohTarget) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "OK")
}

func (t *odohTarget) odohQueryHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Validate method and content type
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	if r.Header.Get("Content-Type") != odohContentType {
		http.Error(w, "Bad content type", http.StatusBadRequest)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Read encrypted query
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	// Parse ODoH message
	odohMessage, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		http.Error(w, "Invalid ODoH message", http.StatusBadRequest)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Decrypt query
	decryptStart := time.Now()
	query, responseCtx, err := t.keyPair.DecryptQuery(odohMessage)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	targetDecryptSeconds.Observe(time.Since(decryptStart).Seconds())

	// Parse DNS query
	dnsQuery := new(dns.Msg)
	if err := dnsQuery.Unpack(query.Message()); err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	if t.logQueries && len(dnsQuery.Question) > 0 {
		log.Infof("Query: %s %s", dnsQuery.Question[0].Name, dns.TypeToString[dnsQuery.Question[0].Qtype])
	}

	// Resolve upstream
	resolveStart := time.Now()
	response, _, err := t.dnsClient.Exchange(dnsQuery, t.upstream)
	if err != nil {
		http.Error(w, "Upstream resolution failed", http.StatusBadGateway)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	targetResolutionSeconds.Observe(time.Since(resolveStart).Seconds())

	// Pack DNS response
	packedResponse, err := response.Pack()
	if err != nil {
		http.Error(w, "Failed to pack response", http.StatusInternalServerError)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Create ODoH response and encrypt
	encryptStart := time.Now()
	odohResponse := odoh.CreateObliviousDNSResponse(packedResponse, 0)
	encryptedResponse, err := responseCtx.EncryptResponse(odohResponse)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	targetEncryptSeconds.Observe(time.Since(encryptStart).Seconds())

	// Send response
	w.Header().Set("Content-Type", odohContentType)
	w.Write(encryptedResponse.Marshal())

	targetRequestsTotal.WithLabelValues("success").Inc()
	targetLatencySeconds.Observe(time.Since(start).Seconds())
}