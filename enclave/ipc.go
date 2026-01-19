package enclave

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// IPCServer handles Unix socket IPC with the proxy.
type IPCServer struct {
	listener net.Listener
	handler  RequestHandler
}

// RequestHandler processes incoming IPC requests.
type RequestHandler interface {
	HandleProcess(blobB, clientIP string) *Response
	HandleStore(query, response string, ttl int) *Response
	HandleStoreEncrypted(query, encryptedResponse string, ttl int) *Response
	HandleGetPubKey() *Response
	HandleHealth() *Response
}

// NewIPCServer creates a new IPC server on the given socket path.
func NewIPCServer(socketPath string, handler RequestHandler) (*IPCServer, error) {
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return &IPCServer{
		listener: listener,
		handler:  handler,
	}, nil
}

// Serve accepts connections and handles requests.
func (s *IPCServer) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConnection(conn)
	}
}

// Close closes the listener.
func (s *IPCServer) Close() error {
	return s.listener.Close()
}

func (s *IPCServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		req, err := readMessage(conn)
		if err != nil {
			if err != io.EOF {
				// Log error in production
			}
			return
		}

		resp := s.dispatch(req)
		if err := writeMessage(conn, resp); err != nil {
			return
		}
	}
}

func (s *IPCServer) dispatch(req *Request) *Response {
	switch req.Type {
	case MsgTypeProcess:
		return s.handler.HandleProcess(req.BlobB, req.ClientIP)
	case MsgTypeStore:
		return s.handler.HandleStore(req.Query, req.Response, req.TTL)
	case MsgTypeStoreEncrypted:
		return s.handler.HandleStoreEncrypted(req.Query, req.EncryptedResponse, req.TTL)
	case MsgTypeGetPubKey:
		return s.handler.HandleGetPubKey()
	case MsgTypeHealth:
		return s.handler.HandleHealth()
	default:
		return &Response{
			Status: StatusError,
			Error:  "unknown message type",
		}
	}
}

// Wire format: [4 bytes: length][JSON payload]

func readMessage(r io.Reader) (*Request, error) {
	// Read length prefix
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	// Sanity check
	if length > 1<<20 { // 1MB max
		return nil, fmt.Errorf("message too large: %d", length)
	}

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return &req, nil
}

func writeMessage(w io.Writer, resp *Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Write length prefix
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}

	// Write payload
	_, err = w.Write(payload)
	return err
}
