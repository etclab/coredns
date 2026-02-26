// Package codohtarget implements an ODoH target server per RFC 9230.
package codohtarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/coredns/coredns/enclave"
	"github.com/coredns/coredns/plugin/codohtarget/cover"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("codohtarget")

const odohContentType = "application/oblivious-dns-message"

// coverSampler abstracts cover domain sampling for testability.
type coverSampler interface {
	Sample(k int, exclude string) []string
}

// coverResolver abstracts cover DNS resolution for testability.
type coverResolver interface {
	Resolve(ctx context.Context, domains []string) []cover.ResolvedCover
}

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

	// Cover response config
	coverCount       int            // k cover domains per query (0 = disabled)
	coverSampler     coverSampler   // domain sampler
	coverResolver    coverResolver  // DNS resolver for covers
	proxyCallbackURL string         // proxy base URL for POST /cache-insert
	callbackClient   *http.Client   // TLS-configured client for proxy callback

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

	// Initialize cover responses
	if err := t.initCoverResponses(); err != nil {
		return fmt.Errorf("cover init: %w", err)
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

// initCoverResponses loads cover config from env vars and initializes sampler + resolver.
func (t *odohTarget) initCoverResponses() error {
	t.coverCount = envInt("CODOH_COVER_COUNT", 3)
	t.proxyCallbackURL = os.Getenv("CODOH_PROXY_CALLBACK_URL")

	if t.proxyCallbackURL == "" {
		log.Info("CODOH_PROXY_CALLBACK_URL not set; cache-insert delivery disabled")
		return nil
	}

	// Callback client with TLS skip-verify for self-signed dev certs
	t.callbackClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	domainFile := os.Getenv("CODOH_COVER_DOMAIN_FILE")
	if t.coverCount > 0 && domainFile == "" {
		return fmt.Errorf("CODOH_COVER_DOMAIN_FILE required when CODOH_COVER_COUNT > 0")
	}

	if t.coverCount > 0 {
		popularCutoff := envInt("CODOH_COVER_POPULAR_CUTOFF", 10000)
		popularRatio := envFloat("CODOH_COVER_POPULAR_RATIO", 0.8)

		sampler, err := cover.NewSampler(domainFile, popularCutoff, popularRatio)
		if err != nil {
			return err
		}
		t.coverSampler = sampler
		log.Infof("Cover sampler loaded (k=%d, cutoff=%d, ratio=%.2f)", t.coverCount, popularCutoff, popularRatio)

		resolverAddr := os.Getenv("CODOH_COVER_RESOLVER")
		if resolverAddr == "" {
			resolverAddr = "127.0.0.1:53"
		}
		timeout := time.Duration(envInt("CODOH_COVER_TIMEOUT_MS", 2000)) * time.Millisecond
		t.coverResolver = cover.NewResolver(resolverAddr, timeout)
		log.Infof("Cover resolver: %s (timeout %v)", resolverAddr, timeout)
	} else {
		log.Info("Cover responses disabled (CODOH_COVER_COUNT=0)")
	}

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

	// Unpad Q_T (CODoH clients pad queries to fixed bucket size for G3)
	body, err = enclave.UnpadFromBucket(body)
	if err != nil {
		http.Error(w, "Invalid padded query", http.StatusBadRequest)
		targetRequestsTotal.WithLabelValues("error").Inc()
		return
	}

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

	// Send ODoH response immediately (before cache-insert)
	w.Header().Set("Content-Type", odohContentType)
	w.Write(encryptedResponse.Marshal())

	targetRequestsTotal.WithLabelValues("success").Inc()
	targetLatencySeconds.Observe(time.Since(start).Seconds())

	// Launch async cache-insert with covers (fire-and-forget)
	if enclavePubKey := r.Header.Get("X-Enclave-PubKey"); enclavePubKey != "" && t.proxyCallbackURL != "" {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(enclavePubKey)
		if err == nil && len(dnsQuery.Question) > 0 {
			go t.prepareCacheInsert(pubKeyBytes, dnsQuery, packedResponse, ttl)
		}
	}
}

// cacheInsertPayload is the JSON body POSTed to the proxy's /cache-insert endpoint.
type cacheInsertPayload struct {
	EncryptedBlob string `json:"encrypted_blob"`
	Signature     string `json:"signature"`
}

// prepareCacheInsert builds a multi-entry bundle (real + k covers), encrypts,
// signs, and POSTs to the proxy's /cache-insert endpoint.
func (t *odohTarget) prepareCacheInsert(pubKeyBytes []byte, dnsQuery *dns.Msg, packedResponse []byte, ttl uint32) {
	q := dnsQuery.Question[0]
	canonicalQuery := enclave.CanonicalizeQuery(q.Name, q.Qtype)
	now := time.Now().Unix()

	// Real entry
	realEntry := enclave.CacheInsertBundle{
		TTL:            ttl,
		Timestamp:      now,
		CanonicalQuery: canonicalQuery,
		DNSResponse:    packedResponse,
	}

	entries := []enclave.CacheInsertBundle{realEntry}

	// Sample and resolve covers
	if t.coverCount > 0 && t.coverSampler != nil && t.coverResolver != nil {
		coverDomains := t.coverSampler.Sample(t.coverCount, q.Name)
		resolved := t.coverResolver.Resolve(context.Background(), coverDomains)

		if len(resolved) == 0 {
			// All covers failed → drop entire bundle (D6)
			log.Warning("All cover resolutions failed; dropping cache-insert bundle")
			return
		}

		for _, rc := range resolved {
			coverCanonical := enclave.CanonicalizeQuery(rc.Domain, dns.TypeA)
			entries = append(entries, enclave.CacheInsertBundle{
				TTL:            rc.TTL,
				Timestamp:      now,
				CanonicalQuery: coverCanonical,
				DNSResponse:    rc.DNSResponse,
			})
		}
	}

	// Marshal multi-bundle
	plaintext, err := enclave.MarshalMultiBundle(entries)
	if err != nil {
		log.Warningf("Failed to marshal multi-bundle: %v", err)
		return
	}

	// HPKE-encrypt to enclave
	encrypted, err := EncryptForEnclave(pubKeyBytes, plaintext)
	if err != nil {
		log.Warningf("Failed to encrypt cache-insert for enclave: %v", err)
		return
	}

	payload := cacheInsertPayload{
		EncryptedBlob: base64.StdEncoding.EncodeToString(encrypted),
	}

	// Sign H(plaintext_bundle) with Ed25519
	if t.signingKey != nil {
		hash := sha256.Sum256(plaintext)
		signature := t.signingKey.Sign(hash[:])
		payload.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	// POST to proxy
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		log.Warningf("Failed to marshal cache-insert payload: %v", err)
		return
	}

	resp, err := t.callbackClient.Post(t.proxyCallbackURL+"/cache-insert", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		log.Warningf("Failed to POST cache-insert to proxy: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warningf("Proxy cache-insert returned status %d", resp.StatusCode)
	}
}

// extractMinimalTTL determines the appropriate TTL for caching based on DNS response type.
// For negative responses (NXDOMAIN, NODATA), applies RFC 2308 §5:
//
//	negative_cache_ttl = min(SOA.TTL, SOA.MINIMUM)
//
// CoreDNS's dnsutil.MinimalTTL only checks SOA.TTL (the header TTL), not the
// SOA RDATA MINIMUM field. We patch the result for negative responses here.
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
	result := uint32(ttl.Seconds())

	// RFC 2308 §5: for negative responses, cap TTL at SOA MINIMUM field.
	if responseType == response.NameError || responseType == response.NoData {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				if soa.Minttl < result {
					result = soa.Minttl
				}
				break
			}
		}
	}

	return result
}

// envInt reads an env var as int, returning defaultVal if unset or unparseable.
func envInt(key string, defaultVal int) int {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// envFloat reads an env var as float64, returning defaultVal if unset or unparseable.
func envFloat(key string, defaultVal float64) float64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultVal
	}
	return v
}
