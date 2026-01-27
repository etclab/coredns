// Package codohtarget implements an ODoH target server per RFC 9230.
package codohtarget

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	clog "github.com/coredns/coredns/plugin/pkg/log"
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

	// Token issuance config
	tokenEnabled     bool
	epochDuration    time.Duration
	rateLimit        int
	masterSecretFile string // Path to hex-encoded 32-byte secret

	// Enclave attestation config
	enclaveURL       string // URL of enclave's attestation endpoint (e.g., https://proxy:8444)
	expectedMRSigner []byte // Expected MRSIGNER (32 bytes)

	// Signing key for target response authentication
	signingKeyPath string
	signingKey     *SigningKey

	keyPair   odoh.ObliviousDoHKeyPair
	dnsClient *dns.Client

	// Token issuance state
	epochs    *epochManager
	limiter   *rateLimiter

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

	// Initialize token issuance if enabled
	if t.tokenEnabled {
		var masterSecret []byte
		if t.masterSecretFile != "" {
			// Load from file (shared with enclave)
			masterSecret, err = loadMasterSecretFromFile(t.masterSecretFile)
			if err != nil {
				return err
			}
			log.Infof("Loaded master secret from %s", t.masterSecretFile)
		} else {
			// Generate random (standalone mode)
			masterSecret, err = generateMasterSecret()
			if err != nil {
				return err
			}
			log.Warning("Using random master secret (not shared with enclave)")
		}

		// Load signing key (if configured)
		if t.signingKeyPath != "" {
			t.signingKey, err = LoadOrGenerateSigningKey(t.signingKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load signing key: %w", err)
			}
			log.Infof("Loaded signing key from %s", t.signingKeyPath)
		}

		// Provision secret to enclave via attestation
		if t.enclaveURL != "" {
			log.Infof("Provisioning master secret to enclave at %s", t.enclaveURL)
			if err := VerifyEnclaveAndProvision(t.enclaveURL, t.expectedMRSigner, masterSecret, t.signingKey); err != nil {
				return fmt.Errorf("enclave provisioning failed: %w", err)
			}
			log.Info("Master secret provisioned to enclave successfully")
		}

		t.epochs, err = newEpochManager(masterSecret, t.epochDuration)
		if err != nil {
			return err
		}
		t.limiter = newRateLimiter(t.rateLimit)
		log.Infof("Token issuance enabled: epoch=%s, limit=%d/epoch", t.epochDuration, t.rateLimit)
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

	// Token routes
	if t.tokenEnabled {
		t.mux.HandleFunc("/token", t.tokenHandler)
		t.mux.HandleFunc("/verify", t.verifyHandler)
	}

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

	// If enclave public key provided, encrypt raw DNS for cache
	if enclavePubKey := r.Header.Get("X-Enclave-PubKey"); enclavePubKey != "" {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(enclavePubKey)
		if err == nil {
			encryptedForCache, err := EncryptForEnclave(pubKeyBytes, packedResponse)
			if err == nil {
				w.Header().Set("X-Enclave-Cache", base64.StdEncoding.EncodeToString(encryptedForCache))

				// Sign the response if signing key is configured
				if t.signingKey != nil && len(dnsQuery.Question) > 0 {
					// Canonicalize query: "name:qtype" (matches client's CanonicalizeQuery format)
					q := dnsQuery.Question[0]
					canonicalQuery := fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.Qtype)

					// Get blob B for signature binding
					blobB := r.Header.Get("X-ODoH-Blob")

					// Compute signature: Sign(H(response || query || B))
					toSign := ComputeSignatureInput(packedResponse, canonicalQuery, blobB)
					signature := t.signingKey.Sign(toSign)

					w.Header().Set("X-Enclave-Cache-Sig", base64.StdEncoding.EncodeToString(signature))
					w.Header().Set("X-Enclave-Cache-Query", canonicalQuery)
				}
			} else {
				log.Warningf("Failed to encrypt for enclave cache: %v", err)
			}
		} else {
			log.Warningf("Invalid X-Enclave-PubKey encoding: %v", err)
		}
	}

	// Send response
	w.Header().Set("Content-Type", odohContentType)
	w.Write(encryptedResponse.Marshal())

	targetRequestsTotal.WithLabelValues("success").Inc()
	targetLatencySeconds.Observe(time.Since(start).Seconds())
}

// tokenHandler handles batch VOPRF token issuance.
// Input format: count (1 byte) || blinded_elements (count * 33 bytes)
// Output format: count (1 byte) || evaluated_elements (count * 33 bytes)
func (t *odohTarget) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rotate epoch if needed
	if err := t.epochs.rotateIfNeeded(); err != nil {
		log.Errorf("Epoch rotation failed: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		tokensIssuedTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	if len(body) < 1 {
		http.Error(w, `{"error":"malformed_token"}`, http.StatusBadRequest)
		tokensIssuedTotal.WithLabelValues("error").Inc()
		return
	}

	count := int(body[0])
	if count == 0 || count > t.rateLimit {
		http.Error(w, `{"error":"invalid_count"}`, http.StatusBadRequest)
		tokensIssuedTotal.WithLabelValues("error").Inc()
		return
	}

	// Check rate limit
	clientIP := getClientIP(r)
	if !t.limiter.allow(clientIP, count, t.epochs.epoch()) {
		http.Error(w, `{"error":"rate_limit_exceeded"}`, http.StatusForbidden)
		tokensIssuedTotal.WithLabelValues("rate_limited").Inc()
		return
	}

	// Evaluate blinded inputs
	result, err := t.epochs.evaluateBatch(body)
	if err != nil {
		log.Errorf("Token evaluation failed: %v", err)
		http.Error(w, `{"error":"evaluation_failed"}`, http.StatusBadRequest)
		tokensIssuedTotal.WithLabelValues("error").Inc()
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(result)
	tokensIssuedTotal.WithLabelValues("success").Inc()
}

// verifyHandler verifies a token for the current epoch.
// Input format: epoch (4 bytes) || input (32 bytes) || output (32 bytes) = 68 bytes
func (t *odohTarget) verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rotate epoch if needed
	if err := t.epochs.rotateIfNeeded(); err != nil {
		log.Errorf("Epoch rotation failed: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Read token
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"malformed_token"}`, http.StatusBadRequest)
		tokensVerifiedTotal.WithLabelValues("error").Inc()
		return
	}
	defer r.Body.Close()

	// Token format: epoch (4) || input (32) || output (32) = 68 bytes
	if len(body) != 68 {
		http.Error(w, `{"error":"malformed_token"}`, http.StatusBadRequest)
		tokensVerifiedTotal.WithLabelValues("error").Inc()
		return
	}

	// Check epoch
	tokenEpoch := uint32(body[0])<<24 | uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3])
	if tokenEpoch != t.epochs.epoch() {
		http.Error(w, `{"error":"expired_epoch"}`, http.StatusForbidden)
		tokensVerifiedTotal.WithLabelValues("expired").Inc()
		return
	}

	input := body[4:36]  // 32 bytes
	output := body[36:]  // 32 bytes (OPRF finalized output)

	// Verify token
	if !t.epochs.verify(input, output) {
		log.Infof("Token verification failed: epoch=%d, input=%x", tokenEpoch, input[:8])
		http.Error(w, `{"error":"invalid_token"}`, http.StatusForbidden)
		tokensVerifiedTotal.WithLabelValues("invalid").Inc()
		return
	}

	w.WriteHeader(http.StatusOK)
	tokensVerifiedTotal.WithLabelValues("valid").Inc()
}

// getClientIP extracts client IP from request.
func getClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := net.ParseIP(xff); ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}