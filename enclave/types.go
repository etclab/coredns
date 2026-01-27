// Package enclave implements the SGX enclave for CODoH token verification and caching.
package enclave

// IPC Message Types
const (
	MsgTypeProcess        = "process"
	MsgTypeStoreEncrypted = "store_encrypted"
	MsgTypeGetPubKey      = "get_pubkey"
	MsgTypeHealth         = "health"
	MsgTypeReady          = "ready" // Returns provisioning status
)

// IPC Response Status
const (
	StatusHit   = "hit"
	StatusMiss  = "miss"
	StatusError = "error"
	StatusOK    = "ok"
)

// Request is the incoming IPC message from proxy.
type Request struct {
	Type              string `json:"type"`
	BlobB             string `json:"blob_b,omitempty"`             // base64, for process and store_encrypted
	ClientIP          string `json:"client_ip,omitempty"`          // for process
	Query             string `json:"query,omitempty"`              // for store_encrypted
	Response          string `json:"response,omitempty"`           // base64, for store (plaintext) - DEPRECATED
	EncryptedResponse string `json:"encrypted_response,omitempty"` // base64, for store_encrypted (HPKE encrypted)
	Signature         string `json:"signature,omitempty"`          // base64, Ed25519 signature for store_encrypted
	TTL               int    `json:"ttl,omitempty"`                // seconds, for store_encrypted
}

// Response is the outgoing IPC message to proxy.
type Response struct {
	Status   string `json:"status"`
	Response string `json:"response,omitempty"` // base64, encrypted response for hit
	Query    string `json:"query,omitempty"`    // canonicalized query for miss
	Kc       string `json:"kc,omitempty"`       // base64, ephemeral key for encrypting miss response
	Error    string `json:"error,omitempty"`    // error description
	PubKey   string `json:"pubkey,omitempty"`   // base64, for get_pubkey
	Ready    bool   `json:"ready,omitempty"`    // for ready check (provisioning status)
}

// BlobB is the decrypted content of the encrypted blob from client.
// B = Enc_{pk_E}(token || query || k_c)
type BlobB struct {
	Epoch uint32 // 4 bytes
	Input []byte // 32 bytes - VOPRF input
	Token []byte // 32 bytes - VOPRF output
	Query string // variable - canonicalized query (e.g., "example.com.:A")
	Kc    []byte // 32 bytes - ephemeral symmetric key
}

// Error codes for IPC responses.
const (
	ErrInvalidBlob   = "invalid_blob"
	ErrDecryptFailed = "decrypt_failed"
	ErrInvalidToken  = "invalid_token"
	ErrTokenExpired  = "token_expired"
	ErrTokenSpent    = "token_spent"
	ErrInternal      = "internal_error"
)
