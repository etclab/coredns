// Package codohtarget implements an ODoH target server per RFC 9230.
package codohtarget

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/coredns/coredns/enclave"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("codohtarget")

const odohContentType = "application/oblivious-dns-message"

type odohTarget struct {
	addr       string // :8443
	tlsCert    string
	tlsKey     string
	upstream   string // 8.8.8.8:53
	logQueries bool

	// Enclave attestation config
	enclaveURL       string // URL of enclave's attestation endpoint (e.g., https://proxy:8444)
	expectedMRSigner []byte // Expected MRSIGNER (32 bytes)

	// Signing key for target response authentication
	signingKeyPath string
	signingKey     *SigningKey

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

	// Load signing key (if configured)
	if t.signingKeyPath != "" {
		t.signingKey, err = LoadOrGenerateSigningKey(t.signingKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load signing key: %w", err)
		}
		log.Infof("Loaded signing key from %s", t.signingKeyPath)
	}

	// Provision signing pubkey to enclave via attestation
	if t.enclaveURL != "" && t.signingKey != nil {
		log.Infof("Provisioning signing pubkey to enclave at %s", t.enclaveURL)
		if err := ProvisionSigningKey(t.enclaveURL, t.expectedMRSigner, t.signingKey); err != nil {
			return fmt.Errorf("enclave provisioning failed: %w", err)
		}
		log.Info("Signing pubkey provisioned to enclave successfully")
	}

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
	dnsResponse, _, err := t.dnsClient.Exchange(dnsQuery, t.upstream)
	if err != nil {
		http.Error(w, "Upstream resolution failed", http.StatusBadGateway)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	targetResolutionSeconds.Observe(time.Since(resolveStart).Seconds())

	// Extract minimal TTL from response
	ttl := extractMinimalTTL(dnsResponse)

	// Pack DNS response
	packedResponse, err := dnsResponse.Pack()
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

	// Build cache-insert blob if enclave public key provided
	if enclavePubKey := r.Header.Get("X-Enclave-PubKey"); enclavePubKey != "" {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(enclavePubKey)
		if err == nil && len(dnsQuery.Question) > 0 {
			t.prepareCacheInsert(w, pubKeyBytes, dnsQuery, packedResponse, ttl)
		}
	}

	// Send ODoH response
	w.Header().Set("Content-Type", odohContentType)
	w.Write(encryptedResponse.Marshal())

	targetRequestsTotal.WithLabelValues("success").Inc()
	targetLatencySeconds.Observe(time.Since(start).Seconds())
}

// prepareCacheInsert builds a cache-insert bundle, encrypts it to pk_E, signs it,
// and sets the appropriate response headers.
func (t *odohTarget) prepareCacheInsert(w http.ResponseWriter, pubKeyBytes []byte, dnsQuery *dns.Msg, packedResponse []byte, ttl uint32) {
	q := dnsQuery.Question[0]
	canonicalQuery := fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.Qtype)

	bundle := &enclave.CacheInsertBundle{
		TTL:            ttl,
		Timestamp:      time.Now().Unix(),
		CanonicalQuery: canonicalQuery,
		DNSResponse:    packedResponse,
	}

	plaintext := enclave.MarshalCacheInsertBundle(bundle)

	// HPKE-encrypt to enclave
	encrypted, err := EncryptForEnclave(pubKeyBytes, plaintext)
	if err != nil {
		log.Warningf("Failed to encrypt cache-insert for enclave: %v", err)
		return
	}
	w.Header().Set("X-Enclave-Cache", base64.StdEncoding.EncodeToString(encrypted))

	// Sign H(plaintext_bundle) with Ed25519
	if t.signingKey != nil {
		hash := sha256.Sum256(plaintext)
		signature := t.signingKey.Sign(hash[:])
		w.Header().Set("X-Enclave-Cache-Sig", base64.StdEncoding.EncodeToString(signature))
	}
}

// extractMinimalTTL determines the appropriate TTL for caching based on DNS response type
func extractMinimalTTL(msg *dns.Msg) uint32 {
	var responseType response.Type
	if msg.Rcode == dns.RcodeSuccess {
		if len(msg.Answer) > 0 {
			responseType = response.NoError
		} else {
			responseType = response.NoData
		}
	} else if msg.Rcode == dns.RcodeNameError {
		responseType = response.NameError
	} else {
		responseType = response.OtherError
	}

	ttl := dnsutil.MinimalTTL(msg, responseType)
	return uint32(ttl.Seconds())
}

// getClientIP extracts client IP from request.
func getClientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := net.ParseIP(xff); ip != nil {
			return ip
		}
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}
