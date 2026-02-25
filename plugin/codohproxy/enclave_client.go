package codohproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coredns/coredns/enclave"
)

// EnclaveClient communicates with the SGX enclave over Unix socket.
// Maintains a small connection pool to amortize dial cost across requests.
type EnclaveClient struct {
	socketPath string
	mu         sync.Mutex
	healthy    bool
	pool       chan net.Conn
}

// enclaveResponse is the parsed binary IPC response from the enclave.
type enclaveResponse struct {
	Status  byte
	Payload []byte
}

// NewEnclaveClient creates a new enclave client with a connection pool.
func NewEnclaveClient(socketPath string) *EnclaveClient {
	return &EnclaveClient{
		socketPath: socketPath,
		healthy:    false,
		pool:       make(chan net.Conn, 4),
	}
}

// Close drains the connection pool and closes all idle connections.
func (c *EnclaveClient) Close() {
	for {
		select {
		case conn := <-c.pool:
			conn.Close()
		default:
			return
		}
	}
}

// getConn returns a pooled connection or dials a new one.
func (c *EnclaveClient) getConn() (net.Conn, error) {
	select {
	case conn := <-c.pool:
		return conn, nil
	default:
		return net.DialTimeout("unix", c.socketPath, 5*time.Second)
	}
}

// putConn returns a connection to the pool, or closes it if the pool is full.
func (c *EnclaveClient) putConn(conn net.Conn) {
	select {
	case c.pool <- conn:
	default:
		conn.Close()
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

// GetPublicKey retrieves the enclave's HPKE public key as raw bytes.
func (c *EnclaveClient) GetPublicKey() ([]byte, error) {
	resp, err := c.sendBinaryRequest(enclave.BinMsgGetPubKey, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != enclave.BinStatusOK {
		return nil, fmt.Errorf("get pubkey failed: %s", string(resp.Payload))
	}
	return resp.Payload, nil
}

// ProcessQE sends raw Q_E bytes to the enclave for HPKE decryption + cache lookup.
// Returns the enclave response (hit with encrypted cached response, or miss with dummy).
func (c *EnclaveClient) ProcessQE(qe []byte) (*enclaveResponse, error) {
	return c.sendBinaryRequest(enclave.BinMsgProcess, qe)
}

// StoreCacheInsert sends raw HPKE-encrypted cache-insert blob + signature to the enclave.
// Wire payload: [4B BE blob_len][blob][sig]
func (c *EnclaveClient) StoreCacheInsert(blob, sig []byte) error {
	payload := make([]byte, 4+len(blob)+len(sig))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(blob)))
	copy(payload[4:], blob)
	copy(payload[4+len(blob):], sig)

	resp, err := c.sendBinaryRequest(enclave.BinMsgStoreEncrypted, payload)
	if err != nil {
		return err
	}
	if resp.Status != enclave.BinStatusOK {
		return fmt.Errorf("store cache insert failed: %s", string(resp.Payload))
	}
	return nil
}

// CheckHealth checks if the enclave is responding.
func (c *EnclaveClient) CheckHealth() error {
	resp, err := c.sendBinaryRequest(enclave.BinMsgHealth, nil)
	if err != nil {
		c.setHealthy(false)
		return err
	}
	if resp.Status != enclave.BinStatusOK {
		c.setHealthy(false)
		return fmt.Errorf("health check failed: %s", string(resp.Payload))
	}
	c.setHealthy(true)
	return nil
}

// sendBinaryRequest sends a binary IPC request and reads the response.
// Wire format: [4B BE total_len][1B msgType][payload]
// Response:    [4B BE total_len][1B status][payload]
func (c *EnclaveClient) sendBinaryRequest(msgType byte, payload []byte) (*enclaveResponse, error) {
	conn, err := c.getConn()
	if err != nil {
		c.setHealthy(false)
		return nil, fmt.Errorf("connect to enclave: %w", err)
	}

	// Write: [4B len][1B type][payload]
	totalLen := 1 + len(payload)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := binary.Write(conn, binary.BigEndian, uint32(totalLen)); err != nil {
		conn.Close()
		c.setHealthy(false)
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write([]byte{msgType}); err != nil {
		conn.Close()
		c.setHealthy(false)
		return nil, fmt.Errorf("write type: %w", err)
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			c.setHealthy(false)
			return nil, fmt.Errorf("write payload: %w", err)
		}
	}
	// Read response: [4B len][1B status][payload]
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var respLen uint32
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		conn.Close()
		c.setHealthy(false)
		return nil, fmt.Errorf("read length: %w", err)
	}

	const maxIPCResponseSize = 1 << 16
	if respLen > maxIPCResponseSize {
		conn.Close()
		c.setHealthy(false)
		return nil, fmt.Errorf("response too large: %d", respLen)
	}
	if respLen < 1 {
		conn.Close()
		c.setHealthy(false)
		return nil, fmt.Errorf("response too short")
	}

	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		c.setHealthy(false)
		return nil, fmt.Errorf("read payload: %w", err)
	}
	// Clear deadlines and return to pool
	conn.SetDeadline(time.Time{})
	c.putConn(conn)

	resp := &enclaveResponse{
		Status:  buf[0],
		Payload: buf[1:],
	}

	c.setHealthy(true)
	return resp, nil
}
