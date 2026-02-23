package codohproxy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// EnclaveClient communicates with the SGX enclave over Unix socket.
// Each IPC call opens a new per-request connection (~50µs for Unix socket).
type EnclaveClient struct {
	socketPath string
	mu         sync.Mutex
	healthy    bool
}

// IPC Message Types (must match enclave/types.go)
const (
	msgTypeProcess        = "process"
	msgTypeStoreEncrypted = "store_encrypted"
	msgTypeGetPubKey      = "get_pubkey"
	msgTypeHealth         = "health"
)

// IPC Response Status
const (
	statusError      = "error"
	statusOK         = "ok"
	statusKeyRotated = "key_rotated"
)

// EnclaveRequest is the IPC request to the enclave.
type EnclaveRequest struct {
	Type          string `json:"type"`
	QE            string `json:"qe,omitempty"`             // base64 Q_E for process
	EncryptedBlob string `json:"encrypted_blob,omitempty"` // base64 HPKE-encrypted cache-insert blob
	Signature     string `json:"signature,omitempty"`       // base64 Ed25519 signature
}

// EnclaveResponse is the IPC response from the enclave.
type EnclaveResponse struct {
	Status   string `json:"status"`
	Response string `json:"response,omitempty"` // base64, encrypted response blob (hit or dummy)
	Error    string `json:"error,omitempty"`
	PubKey   string `json:"pubkey,omitempty"` // base64, for get_pubkey
}

// NewEnclaveClient creates a new enclave client.
func NewEnclaveClient(socketPath string) *EnclaveClient {
	return &EnclaveClient{
		socketPath: socketPath,
		healthy:    false,
	}
}

// IsHealthy returns whether the enclave is reachable.
func (c *EnclaveClient) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.healthy
}

// setHealthy updates the health status.
func (c *EnclaveClient) setHealthy(h bool) {
	c.mu.Lock()
	c.healthy = h
	c.mu.Unlock()
}

// GetPublicKey retrieves the enclave's HPKE public key.
func (c *EnclaveClient) GetPublicKey() (string, error) {
	resp, err := c.sendRequest(&EnclaveRequest{Type: msgTypeGetPubKey})
	if err != nil {
		return "", err
	}
	if resp.Status != statusOK {
		return "", fmt.Errorf("get pubkey failed: %s", resp.Error)
	}
	return resp.PubKey, nil
}

// ProcessQE sends a Q_E to the enclave for HPKE decryption + cache lookup.
// Returns the enclave response (hit with encrypted cached response, or miss with dummy).
func (c *EnclaveClient) ProcessQE(qe string) (*EnclaveResponse, error) {
	return c.sendRequest(&EnclaveRequest{
		Type: msgTypeProcess,
		QE:   qe,
	})
}

// StoreCacheInsert sends an HPKE-encrypted cache-insert bundle + signature to the enclave.
// Fire-and-forget: caller doesn't need to check the response.
func (c *EnclaveClient) StoreCacheInsert(encryptedBlob, signature string) error {
	resp, err := c.sendRequest(&EnclaveRequest{
		Type:          msgTypeStoreEncrypted,
		EncryptedBlob: encryptedBlob,
		Signature:     signature,
	})
	if err != nil {
		return err
	}
	if resp.Status != statusOK {
		return fmt.Errorf("store cache insert failed: %s", resp.Error)
	}
	return nil
}

// CheckHealth checks if the enclave is responding.
func (c *EnclaveClient) CheckHealth() error {
	resp, err := c.sendRequest(&EnclaveRequest{Type: msgTypeHealth})
	if err != nil {
		c.setHealthy(false)
		return err
	}
	if resp.Status != statusOK {
		c.setHealthy(false)
		return fmt.Errorf("health check failed: %s", resp.Error)
	}
	c.setHealthy(true)
	return nil
}

// sendRequest opens a new Unix socket connection, sends the request, reads the response, and closes.
func (c *EnclaveClient) sendRequest(req *EnclaveRequest) (*EnclaveResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		c.setHealthy(false)
		return nil, fmt.Errorf("connect to enclave: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Marshal request
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Write length prefix + payload
	if err := binary.Write(conn, binary.BigEndian, uint32(len(payload))); err != nil {
		c.setHealthy(false)
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		c.setHealthy(false)
		return nil, fmt.Errorf("write payload: %w", err)
	}

	// Read response length
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		c.setHealthy(false)
		return nil, fmt.Errorf("read length: %w", err)
	}

	const maxIPCResponseSize = 1 << 16
	if length > maxIPCResponseSize {
		c.setHealthy(false)
		return nil, fmt.Errorf("response too large: %d", length)
	}

	// Read response payload
	respPayload := make([]byte, length)
	if _, err := io.ReadFull(conn, respPayload); err != nil {
		c.setHealthy(false)
		return nil, fmt.Errorf("read payload: %w", err)
	}

	var resp EnclaveResponse
	if err := json.Unmarshal(respPayload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	c.setHealthy(true)
	return &resp, nil
}
