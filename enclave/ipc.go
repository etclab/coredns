package enclave

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// IPCServer handles Unix socket IPC with the proxy.
type IPCServer struct {
	listener net.Listener
	handler  RequestHandler
}

// RequestHandler processes incoming binary IPC requests.
type RequestHandler interface {
	HandleProcess(qe []byte) *BinaryResponse
	HandleStoreEncrypted(blob, sig []byte) *BinaryResponse
	HandleGetPubKey() *BinaryResponse
	HandleHealth() *BinaryResponse
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
		msgType, payload, err := readBinaryRequest(conn)
		if err != nil {
			if err != io.EOF {
				// Log error in production
			}
			return
		}

		resp := s.dispatch(msgType, payload)
		if err := writeBinaryResponse(conn, resp); err != nil {
			return
		}
	}
}

func (s *IPCServer) dispatch(msgType byte, payload []byte) *BinaryResponse {
	switch msgType {
	case BinMsgProcess:
		return s.handler.HandleProcess(payload)
	case BinMsgStoreEncrypted:
		// Payload format: [4B BE blob_len][blob][sig]
		if len(payload) < 4 {
			return &BinaryResponse{Status: BinStatusError, Payload: []byte(ErrInvalidBlob)}
		}
		blobLen := binary.BigEndian.Uint32(payload[:4])
		if uint32(len(payload)-4) < blobLen {
			return &BinaryResponse{Status: BinStatusError, Payload: []byte(ErrInvalidBlob)}
		}
		blob := payload[4 : 4+blobLen]
		sig := payload[4+blobLen:]
		return s.handler.HandleStoreEncrypted(blob, sig)
	case BinMsgGetPubKey:
		return s.handler.HandleGetPubKey()
	case BinMsgHealth:
		return s.handler.HandleHealth()
	default:
		return &BinaryResponse{Status: BinStatusError, Payload: []byte("unknown message type")}
	}
}

// Wire format: [4B BE total_len][1B type/status][payload]

// maxIPCMessageSize is the maximum allowed IPC message size (64 KiB).
const maxIPCMessageSize = 1 << 16

func readBinaryRequest(r io.Reader) (msgType byte, payload []byte, err error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}

	if length > maxIPCMessageSize {
		return 0, nil, fmt.Errorf("message too large: %d", length)
	}

	if length < 1 {
		return 0, nil, fmt.Errorf("message too short")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}

	return buf[0], buf[1:], nil
}

func writeBinaryResponse(w io.Writer, resp *BinaryResponse) error {
	totalLen := 1 + len(resp.Payload) // 1B status + payload
	if err := binary.Write(w, binary.BigEndian, uint32(totalLen)); err != nil {
		return err
	}

	if _, err := w.Write([]byte{resp.Status}); err != nil {
		return err
	}

	if len(resp.Payload) > 0 {
		_, err := w.Write(resp.Payload)
		return err
	}
	return nil
}
