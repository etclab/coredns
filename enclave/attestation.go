package enclave

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

// AttestationServer provides SGX remote attestation and secret provisioning endpoints.
// In SGX mode, it generates DCAP quotes binding the enclave's HPKE public key.
// In simulation mode, it still serves endpoints but returns empty quotes.
type AttestationServer struct {
	port        int
	keypair     *EnclaveKeypair
	provisionCh chan<- ProvisionData
	server      *http.Server
	quote       []byte
	ready       bool
	mu          sync.RWMutex
}

// AttestResponse is returned by the /attest endpoint.
type AttestResponse struct {
	Quote  string `json:"quote"`  // Base64-encoded SGX quote
	PubKey string `json:"pubkey"` // Base64-encoded HPKE public key
}

// ProvisionRequest is sent to the /provision endpoint.
type ProvisionRequest struct {
	EncryptedSecret  string `json:"encrypted_secret"`         // Base64-encoded HPKE-encrypted master secret
	SigningPublicKey string `json:"signing_pubkey,omitempty"` // Base64-encoded Ed25519 public key for target response verification
}

// ProvisionData is the data sent through the provisioning channel.
type ProvisionData struct {
	MasterSecret     []byte
	SigningPublicKey []byte
}

// NewAttestationServer creates a new attestation server.
func NewAttestationServer(port int, keypair *EnclaveKeypair, provisionCh chan<- ProvisionData) *AttestationServer {
	return &AttestationServer{
		port:        port,
		keypair:     keypair,
		provisionCh: provisionCh,
	}
}

// GenerateQuote generates an SGX DCAP quote with the public key as user data.
// Returns nil if running in simulation mode (quote generation fails).
func GenerateQuote(pubKey []byte) ([]byte, error) {
	// Try to generate SGX quote using EGo's report package
	// This will fail in simulation mode, which is expected
	quote, err := getRemoteReport(pubKey)
	if err != nil {
		return nil, fmt.Errorf("quote generation failed (simulation mode?): %w", err)
	}
	return quote, nil
}

// Start starts the attestation HTTPS server with EGo's attested TLS.
// This blocks until the server is shut down.
func (s *AttestationServer) Start() error {
	pubKeyBytes, err := s.keypair.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	// Try to generate quote (may fail in simulation mode)
	s.quote, _ = GenerateQuote(pubKeyBytes)
	if s.quote != nil {
		log.Printf("Generated SGX quote (%d bytes)", len(s.quote))
	} else {
		log.Println("Running in simulation mode (no SGX quote)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/attest", s.attestHandler)
	mux.HandleFunc("/provision", s.provisionHandler)
	mux.HandleFunc("/health", s.healthHandler)

	addr := fmt.Sprintf(":%d", s.port)

	// Get TLS config - uses EGo's attested TLS in SGX mode, or self-signed in simulation
	tlsConfig, err := getAttestedTLSConfig()
	if err != nil {
		log.Printf("Using self-signed TLS (simulation mode): %v", err)
		tlsConfig, err = generateSelfSignedTLSConfig()
		if err != nil {
			return fmt.Errorf("generate self-signed TLS: %w", err)
		}
	}

	s.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Attestation server listening on https://0.0.0.0:%d", s.port)
	return s.server.ListenAndServeTLS("", "") // Certs are in TLSConfig
}

// Stop gracefully stops the attestation server.
func (s *AttestationServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// attestHandler returns the SGX quote and public key.
// GET /attest
func (s *AttestationServer) attestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pubKeyBytes, err := s.keypair.PublicKeyBytes()
	if err != nil {
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	resp := AttestResponse{
		Quote:  base64.StdEncoding.EncodeToString(s.quote),
		PubKey: base64.StdEncoding.EncodeToString(pubKeyBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// provisionHandler receives the encrypted master secret.
// POST /provision
func (s *AttestationServer) provisionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	if s.ready {
		s.mu.Unlock()
		http.Error(w, "Already provisioned", http.StatusConflict)
		return
	}
	s.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req ProvisionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Decode encrypted secret
	encryptedSecret, err := base64.StdEncoding.DecodeString(req.EncryptedSecret)
	if err != nil {
		http.Error(w, "Invalid base64 encoding", http.StatusBadRequest)
		return
	}

	// Decrypt using enclave's private key
	masterSecret, err := s.keypair.Decrypt(encryptedSecret)
	if err != nil {
		log.Printf("Failed to decrypt provisioned secret: %v", err)
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	// Validate master secret length
	if len(masterSecret) != 32 {
		http.Error(w, "Invalid secret length", http.StatusBadRequest)
		return
	}

	// Decode signing public key (optional)
	var signingPubKey []byte
	if req.SigningPublicKey != "" {
		signingPubKey, err = base64.StdEncoding.DecodeString(req.SigningPublicKey)
		if err != nil {
			http.Error(w, "Invalid signing pubkey encoding", http.StatusBadRequest)
			return
		}
		if len(signingPubKey) != 32 { // Ed25519 public key is 32 bytes
			http.Error(w, "Invalid signing pubkey length", http.StatusBadRequest)
			return
		}
	}

	// Send to provisioning channel (non-blocking)
	provData := ProvisionData{
		MasterSecret:     masterSecret,
		SigningPublicKey: signingPubKey,
	}
	select {
	case s.provisionCh <- provData:
		s.mu.Lock()
		s.ready = true
		s.mu.Unlock()
		if len(signingPubKey) > 0 {
			log.Println("Master secret and signing pubkey provisioned successfully")
		} else {
			log.Println("Master secret provisioned successfully (no signing key)")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	default:
		http.Error(w, "Provisioning channel full", http.StatusServiceUnavailable)
	}
}

// healthHandler returns health status.
// GET /health
func (s *AttestationServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.ready
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if ready {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"waiting_for_provision"}`))
	}
}

// IsReady returns whether the enclave has been provisioned.
func (s *AttestationServer) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}
