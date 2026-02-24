package enclave

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadBinaryRequest_AcceptsSmallMessage(t *testing.T) {
	// Binary format: [4B len][1B type][payload]
	payload := []byte("hello")
	totalLen := uint32(1 + len(payload))

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, totalLen)
	buf.WriteByte(BinMsgHealth)
	buf.Write(payload)

	msgType, data, err := readBinaryRequest(&buf)
	if err != nil {
		t.Fatalf("expected message to be accepted, got: %v", err)
	}
	if msgType != BinMsgHealth {
		t.Fatalf("expected type 0x%02x, got 0x%02x", BinMsgHealth, msgType)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("payload mismatch: got %x, want %x", data, payload)
	}
}

func TestReadBinaryRequest_TypeOnlyNoPayload(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(1)) // just the type byte
	buf.WriteByte(BinMsgGetPubKey)

	msgType, data, err := readBinaryRequest(&buf)
	if err != nil {
		t.Fatalf("expected type-only message to be accepted, got: %v", err)
	}
	if msgType != BinMsgGetPubKey {
		t.Fatalf("expected type 0x%02x, got 0x%02x", BinMsgGetPubKey, msgType)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(data))
	}
}

func TestReadBinaryRequest_AcceptsBoundarySize(t *testing.T) {
	// Total length exactly at maxIPCMessageSize
	payloadSize := int(maxIPCMessageSize) - 1 // 1B type + (maxIPCMessageSize-1)B payload
	payload := bytes.Repeat([]byte("A"), payloadSize)

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(maxIPCMessageSize))
	buf.WriteByte(BinMsgProcess)
	buf.Write(payload)

	msgType, data, err := readBinaryRequest(&buf)
	if err != nil {
		t.Fatalf("expected boundary-size message to be accepted, got: %v", err)
	}
	if msgType != BinMsgProcess {
		t.Fatalf("expected type 0x%02x, got 0x%02x", BinMsgProcess, msgType)
	}
	if len(data) != payloadSize {
		t.Fatalf("expected payload %d bytes, got %d", payloadSize, len(data))
	}
}

func TestReadBinaryRequest_RejectsOversize(t *testing.T) {
	size := uint32(maxIPCMessageSize + 1)
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, size)

	_, _, err := readBinaryRequest(&buf)
	if err == nil {
		t.Fatal("expected oversize message to be rejected")
	}
}

func TestReadBinaryRequest_RejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0))

	_, _, err := readBinaryRequest(&buf)
	if err == nil {
		t.Fatal("expected zero-length message to be rejected")
	}
}

func TestWriteBinaryResponse_RoundTrip(t *testing.T) {
	resp := &BinaryResponse{
		Status:  BinStatusProcessed,
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	var buf bytes.Buffer
	if err := writeBinaryResponse(&buf, resp); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read back: [4B len][1B status][payload]
	var length uint32
	binary.Read(&buf, binary.BigEndian, &length)
	if int(length) != 1+len(resp.Payload) {
		t.Fatalf("expected length %d, got %d", 1+len(resp.Payload), length)
	}

	status, _ := buf.ReadByte()
	if status != BinStatusProcessed {
		t.Fatalf("expected status 0x%02x, got 0x%02x", BinStatusProcessed, status)
	}

	payload := buf.Bytes()
	if !bytes.Equal(payload, resp.Payload) {
		t.Fatalf("payload mismatch: got %x, want %x", payload, resp.Payload)
	}
}
