package enclave

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestReadMessage_AcceptsSmallMessage(t *testing.T) {
	payload, _ := json.Marshal(&Request{Type: MsgTypeHealth})

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)

	msg, err := readMessage(&buf)
	if err != nil {
		t.Fatalf("expected message to be accepted, got: %v", err)
	}
	if msg.Type != MsgTypeHealth {
		t.Fatalf("expected type %q, got %q", MsgTypeHealth, msg.Type)
	}
}

func TestReadMessage_AcceptsBoundarySize(t *testing.T) {
	// Declared length exactly at maxIPCMessageSize should pass the size check.
	// We verify by constructing a valid JSON payload padded to exactly 65536 bytes.
	base := `{"type":"health","qe":"`
	suffix := `"}`
	padLen := int(maxIPCMessageSize) - len(base) - len(suffix)
	pad := bytes.Repeat([]byte("A"), padLen)
	payload := []byte(base + string(pad) + suffix)

	if len(payload) != int(maxIPCMessageSize) {
		t.Fatalf("test setup: payload is %d bytes, want %d", len(payload), maxIPCMessageSize)
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)

	msg, err := readMessage(&buf)
	if err != nil {
		t.Fatalf("expected %d-byte message to be accepted, got: %v", maxIPCMessageSize, err)
	}
	if msg.Type != MsgTypeHealth {
		t.Fatalf("expected type %q, got %q", MsgTypeHealth, msg.Type)
	}
}

func TestReadMessage_RejectsOversize(t *testing.T) {
	// Declared length of maxIPCMessageSize+1 should be rejected before reading payload
	size := uint32(maxIPCMessageSize + 1)
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, size)

	_, err := readMessage(&buf)
	if err == nil {
		t.Fatal("expected oversize message to be rejected")
	}
}
