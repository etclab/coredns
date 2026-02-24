// Package enclave implements the SGX enclave for CODoH caching.
package enclave

// Binary IPC message types (request direction: proxy → enclave).
const (
	BinMsgProcess        byte = 0x01
	BinMsgStoreEncrypted byte = 0x02
	BinMsgGetPubKey      byte = 0x03
	BinMsgHealth         byte = 0x04
)

// Binary IPC response status codes (response direction: enclave → proxy).
const (
	BinStatusOK         byte = 0x00
	BinStatusProcessed  byte = 0x01
	BinStatusError      byte = 0x02
	BinStatusKeyRotated byte = 0x03
)

// BinaryResponse is the binary IPC response from the enclave.
// Wire format: [4B BE total_len][1B status][payload bytes]
type BinaryResponse struct {
	Status  byte
	Payload []byte
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
