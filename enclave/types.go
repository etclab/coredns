// Package enclave implements the SGX enclave for CODoH caching.
package enclave

// IPC Message Types
const (
	MsgTypeProcess        = "process"
	MsgTypeStoreEncrypted = "store_encrypted"
	MsgTypeGetPubKey      = "get_pubkey"
	MsgTypeHealth         = "health"
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
	Type string `json:"type"`

	// For process: base64-encoded Q_E (HPKE-encrypted query from client)
	QE string `json:"qe,omitempty"`

	// For store_encrypted: base64-encoded HPKE-encrypted cache-insert blob + signature
	EncryptedBlob string `json:"encrypted_blob,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

// Response is the outgoing IPC message to proxy.
type Response struct {
	Status   string `json:"status"`
	Response string `json:"response,omitempty"` // base64, encrypted response blob (hit or dummy)
	Error    string `json:"error,omitempty"`    // error description
	PubKey   string `json:"pubkey,omitempty"`   // base64, for get_pubkey
}

// Error codes for IPC responses.
const (
	ErrInvalidBlob      = "invalid_blob"
	ErrDecryptFailed    = "decrypt_failed"
	ErrHPKEError        = "hpke_error"
	ErrInvalidSignature = "invalid_signature"
	ErrStaleTimestamp   = "stale_timestamp"
	ErrInternal         = "internal_error"
)
