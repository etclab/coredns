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
type EnclaveClient struct {
	socketPath string
	conn       net.Conn
	mu         sync.Mutex
	healthy    bool
}

// IPC Message Types (must match enclave/types.go)
const (
	msgTypeProcess        = "process"
	msgTypeStore          = "store"
	msgTypeStoreEncrypted = "store_encrypted"
	msgTypeGetPubKey      = "get_pubkey"
	msgTypeHealth         = "health"
)

// IPC Response Status
const (
	statusHit   = "hit"
	statusMiss  = "miss"
	statusError = "error"
	statusOK    = "ok"
)

// EnclaveRequest is the IPC request to the enclave.
type EnclaveRequest struct {
	Type              string `json:"type"`
	BlobB             string `json:"blob_b,omitempty"`
	ClientIP          string `json:"client_ip,omitempty"`
	Query             string `json:"query,omitempty"`
	Response          string `json:"response,omitempty"`
	EncryptedResponse string `json:"encrypted_response,omitempty"`
	TTL               int    `json:"ttl,omitempty"`
}

// EnclaveResponse is the IPC response from the enclave.
type EnclaveResponse struct {
	Status   string `json:"status"`
	Response string `json:"response,omitempty"`
	Query    string `json:"query,omitempty"`
	Kc       string `json:"kc,omitempty"`
	Error    string `json:"error,omitempty"`
	PubKey   string `json:"pubkey,omitempty"`
}

// NewEnclaveClient creates a new enclave client.
func NewEnclaveClient(socketPath string) *EnclaveClient {
	return &EnclaveClient{
		socketPath: socketPath,
		healthy:    false,
	}
}

// Connect establishes a connection to the enclave.
func (c *EnclaveClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
	}

	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		c.healthy = false
		return fmt.Errorf("connect to enclave: %w", err)
	}

	c.conn = conn
	c.healthy = true
	return nil
}

// Close closes the connection.
func (c *EnclaveClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.healthy = false
		return err
	}
	return nil
}

// IsHealthy returns whether the enclave connection is healthy.
func (c *EnclaveClient) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.healthy
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

// ProcessRequest sends a blob B to the enclave for processing.
// Returns the response from the enclave.
func (c *EnclaveClient) ProcessRequest(blobB, clientIP string) (*EnclaveResponse, error) {
	return c.sendRequest(&EnclaveRequest{
		Type:     msgTypeProcess,
		BlobB:    blobB,
		ClientIP: clientIP,
	})
}

// StoreCache stores a DNS response in the enclave cache.
func (c *EnclaveClient) StoreCache(query, response string, ttl int) error {
	resp, err := c.sendRequest(&EnclaveRequest{
		Type:     msgTypeStore,
		Query:    query,
		Response: response,
		TTL:      ttl,
	})
	if err != nil {
		return err
	}
	if resp.Status != statusOK {
		return fmt.Errorf("store cache failed: %s", resp.Error)
	}
	return nil
}

// StoreEncrypted stores an HPKE-encrypted DNS response in the enclave cache.
// The enclave will decrypt it using its private key before storing.
func (c *EnclaveClient) StoreEncrypted(query, encryptedResponse string, ttl int) error {
	resp, err := c.sendRequest(&EnclaveRequest{
		Type:              msgTypeStoreEncrypted,
		Query:             query,
		EncryptedResponse: encryptedResponse,
		TTL:               ttl,
	})
	if err != nil {
		return err
	}
	if resp.Status != statusOK {
		return fmt.Errorf("store encrypted failed: %s", resp.Error)
	}
	return nil
}

// CheckHealth checks if the enclave is responding.
func (c *EnclaveClient) CheckHealth() error {
	resp, err := c.sendRequest(&EnclaveRequest{Type: msgTypeHealth})
	if err != nil {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return err
	}
	if resp.Status != statusOK {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return fmt.Errorf("health check failed: %s", resp.Error)
	}
	c.mu.Lock()
	c.healthy = true
	c.mu.Unlock()
	return nil
}

// sendRequest sends a request to the enclave and returns the response.
func (c *EnclaveClient) sendRequest(req *EnclaveRequest) (*EnclaveResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("not connected to enclave")
	}

	// Set deadline
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Marshal request
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Write length prefix + payload
	if err := binary.Write(c.conn, binary.BigEndian, uint32(len(payload))); err != nil {
		c.healthy = false
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := c.conn.Write(payload); err != nil {
		c.healthy = false
		return nil, fmt.Errorf("write payload: %w", err)
	}

	// Read response length
	var length uint32
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		c.healthy = false
		return nil, fmt.Errorf("read length: %w", err)
	}

	// Sanity check
	if length > 1<<20 {
		c.healthy = false
		return nil, fmt.Errorf("response too large: %d", length)
	}

	// Read response payload
	respPayload := make([]byte, length)
	if _, err := io.ReadFull(c.conn, respPayload); err != nil {
		c.healthy = false
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Unmarshal response
	var resp EnclaveResponse
	if err := json.Unmarshal(respPayload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, nil
}
