package codohproxy

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/coredns/coredns/enclave"
)

// mockEnclaveHandler implements enclave.RequestHandler for testing (binary IPC).
type mockEnclaveHandler struct {
	processFunc        func(qe []byte) *enclave.BinaryResponse
	storeEncryptedFunc func(blob, sig []byte) *enclave.BinaryResponse

	// Captured store_encrypted calls
	mu         sync.Mutex
	storeCalls []storeCall
}

type storeCall struct {
	Blob []byte
	Sig  []byte
}

func (m *mockEnclaveHandler) HandleProcess(qe []byte) *enclave.BinaryResponse {
	return m.processFunc(qe)
}

func (m *mockEnclaveHandler) HandleStoreEncrypted(blob, sig []byte) *enclave.BinaryResponse {
	m.mu.Lock()
	// Copy slices since they may reference IPC buffer
	blobCopy := make([]byte, len(blob))
	copy(blobCopy, blob)
	sigCopy := make([]byte, len(sig))
	copy(sigCopy, sig)
	m.storeCalls = append(m.storeCalls, storeCall{Blob: blobCopy, Sig: sigCopy})
	m.mu.Unlock()
	if m.storeEncryptedFunc != nil {
		return m.storeEncryptedFunc(blob, sig)
	}
	return &enclave.BinaryResponse{Status: enclave.BinStatusOK}
}

func (m *mockEnclaveHandler) HandleGetPubKey() *enclave.BinaryResponse {
	// Return 32 bytes of zeros as a mock public key
	return &enclave.BinaryResponse{Status: enclave.BinStatusOK, Payload: make([]byte, 32)}
}

func (m *mockEnclaveHandler) HandleHealth() *enclave.BinaryResponse {
	return &enclave.BinaryResponse{Status: enclave.BinStatusOK, Payload: []byte(`{"started_at":"2024-01-01T00:00:00Z"}`)}
}

func TestProxyHandler_KeyRotated(t *testing.T) {
	// 1. Start mock enclave on temp Unix socket using the real IPC server.
	socketPath := filepath.Join(t.TempDir(), "test-enclave.sock")
	handler := &mockEnclaveHandler{
		processFunc: func(qe []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusKeyRotated}
		},
	}
	ipcServer, err := enclave.NewIPCServer(socketPath, handler)
	if err != nil {
		t.Fatalf("NewIPCServer: %v", err)
	}
	defer ipcServer.Close()
	go ipcServer.Serve()

	// 2. Start mock target returning a fixed ODoH blob.
	targetBody := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oblivious-dns-message")
		w.Write(targetBody)
	}))
	defer targetSrv.Close()

	// 3. Build proxy with real EnclaveClient pointing to mock socket.
	ec := NewEnclaveClient(socketPath)
	if err := ec.CheckHealth(); err != nil {
		t.Fatalf("CheckHealth: %v", err)
	}

	proxy := &odohProxy{
		targetURL:      targetSrv.URL + "/dns-query",
		enclaveEnabled: true,
		enclaveClient:  ec,
		client:         targetSrv.Client(),
	}

	// 4. Build request with Q_E header (triggers enclave path).
	req := httptest.NewRequest("POST", "/proxy", bytes.NewReader([]byte("Q_T body")))
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("X-CoDOH-Query", "dGVzdC1xZQ==") // base64 "test-qe"
	w := httptest.NewRecorder()

	proxy.proxyHandler(w, req)

	// 5. Assert response.
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/oblivious-dns-message" {
		t.Fatalf("expected ODoH content type (degraded), got %q", ct)
	}
	if v := resp.Header.Get("X-CoDOH-Key-Rotated"); v != "true" {
		t.Fatalf("expected X-CoDOH-Key-Rotated: true, got %q", v)
	}
	if v := resp.Header.Get("X-CoDOH-Enclave-Error"); v != "key_rotated" {
		t.Fatalf("expected X-CoDOH-Enclave-Error: key_rotated, got %q", v)
	}
	if !bytes.Equal(body, targetBody) {
		t.Fatalf("body mismatch: got %x, want %x", body, targetBody)
	}
}

func TestProxyHandler_CacheMiss_TwoChunkResponse(t *testing.T) {
	// Verify that a normal cache miss (processed with dummy blob) produces
	// a two-chunk response with application/codoh-response content type.
	socketPath := filepath.Join(t.TempDir(), "test-enclave.sock")
	dummyPayload := []byte{0x01, 0x02, 0x03, 0x04}
	handler := &mockEnclaveHandler{
		processFunc: func(qe []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusProcessed, Payload: dummyPayload}
		},
	}
	ipcServer, err := enclave.NewIPCServer(socketPath, handler)
	if err != nil {
		t.Fatalf("NewIPCServer: %v", err)
	}
	defer ipcServer.Close()
	go ipcServer.Serve()

	targetBody := []byte{0xCA, 0xFE}
	targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oblivious-dns-message")
		w.Write(targetBody)
	}))
	defer targetSrv.Close()

	ec := NewEnclaveClient(socketPath)
	if err := ec.CheckHealth(); err != nil {
		t.Fatalf("CheckHealth: %v", err)
	}

	proxy := &odohProxy{
		targetURL:      targetSrv.URL + "/dns-query",
		enclaveEnabled: true,
		enclaveClient:  ec,
		client:         targetSrv.Client(),
	}

	req := httptest.NewRequest("POST", "/proxy", bytes.NewReader([]byte("Q_T body")))
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("X-CoDOH-Query", "dGVzdC1xZQ==")
	w := httptest.NewRecorder()

	proxy.proxyHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != codohResponseContentType {
		t.Fatalf("expected %s, got %q", codohResponseContentType, ct)
	}

	// Tagged chunk format: [1B type][2B BE len][data] per chunk
	// Both enclave and target chunks should be present (order may vary).
	var gotEnclave, gotTarget []byte

	for len(body) >= 3 {
		chunkType := body[0]
		chunkLen := int(body[1])<<8 | int(body[2])
		if 3+chunkLen > len(body) {
			t.Fatalf("chunk type=%d len=%d exceeds remaining body (%d bytes)", chunkType, chunkLen, len(body)-3)
		}
		chunkData := body[3 : 3+chunkLen]
		body = body[3+chunkLen:]

		switch chunkType {
		case ChunkTypeEnclave:
			gotEnclave = chunkData
		case ChunkTypeTarget:
			gotTarget = chunkData
		default:
			t.Fatalf("unexpected chunk type: %d", chunkType)
		}
	}

	if !bytes.Equal(gotEnclave, dummyPayload) {
		t.Fatalf("enclave chunk mismatch: got %x, want %x", gotEnclave, dummyPayload)
	}
	if !bytes.Equal(gotTarget, targetBody) {
		t.Fatalf("target chunk mismatch: got %x, want %x", gotTarget, targetBody)
	}
}

// --- S5-T5: /cache-insert handler tests ---

func newCacheInsertProxy(t *testing.T, handler *mockEnclaveHandler) (*odohProxy, func()) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "test-enclave.sock")
	ipcServer, err := enclave.NewIPCServer(socketPath, handler)
	if err != nil {
		t.Fatalf("NewIPCServer: %v", err)
	}
	go ipcServer.Serve()

	ec := NewEnclaveClient(socketPath)
	if err := ec.CheckHealth(); err != nil {
		t.Fatalf("CheckHealth: %v", err)
	}

	proxy := &odohProxy{
		enclaveEnabled: true,
		enclaveClient:  ec,
	}
	return proxy, func() { ipcServer.Close() }
}

func TestCacheInsertHandler_ValidPOST(t *testing.T) {
	handler := &mockEnclaveHandler{
		processFunc: func(qe []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusProcessed}
		},
	}
	proxy, cleanup := newCacheInsertProxy(t, handler)
	defer cleanup()

	body := `{"encrypted_blob":"AQIDBA==","signature":"BQYHCA=="}`
	req := httptest.NewRequest("POST", "/cache-insert", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	proxy.cacheInsertHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	// Verify enclave received the store_encrypted call with correct raw bytes
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.storeCalls) != 1 {
		t.Fatalf("expected 1 store call, got %d", len(handler.storeCalls))
	}
	expectedBlob, _ := base64.StdEncoding.DecodeString("AQIDBA==")
	expectedSig, _ := base64.StdEncoding.DecodeString("BQYHCA==")
	if !bytes.Equal(handler.storeCalls[0].Blob, expectedBlob) {
		t.Errorf("blob mismatch: got %x, want %x", handler.storeCalls[0].Blob, expectedBlob)
	}
	if !bytes.Equal(handler.storeCalls[0].Sig, expectedSig) {
		t.Errorf("sig mismatch: got %x, want %x", handler.storeCalls[0].Sig, expectedSig)
	}
}

func TestCacheInsertHandler_InvalidJSON(t *testing.T) {
	handler := &mockEnclaveHandler{
		processFunc: func(qe []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusProcessed}
		},
	}
	proxy, cleanup := newCacheInsertProxy(t, handler)
	defer cleanup()

	req := httptest.NewRequest("POST", "/cache-insert", strings.NewReader("not json{{{"))
	w := httptest.NewRecorder()

	proxy.cacheInsertHandler(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestCacheInsertHandler_MissingBlob(t *testing.T) {
	handler := &mockEnclaveHandler{
		processFunc: func(qe []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusProcessed}
		},
	}
	proxy, cleanup := newCacheInsertProxy(t, handler)
	defer cleanup()

	body := `{"encrypted_blob":"","signature":"BQYHCA=="}`
	req := httptest.NewRequest("POST", "/cache-insert", strings.NewReader(body))
	w := httptest.NewRecorder()

	proxy.cacheInsertHandler(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for empty blob, got %d", w.Code)
	}
}

func TestCacheInsertHandler_EnclaveIPCFail(t *testing.T) {
	handler := &mockEnclaveHandler{
		processFunc: func(qe []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusProcessed}
		},
		storeEncryptedFunc: func(blob, sig []byte) *enclave.BinaryResponse {
			return &enclave.BinaryResponse{Status: enclave.BinStatusError, Payload: []byte("decrypt_failed")}
		},
	}
	proxy, cleanup := newCacheInsertProxy(t, handler)
	defer cleanup()

	body := `{"encrypted_blob":"AQIDBA==","signature":"BQYHCA=="}`
	req := httptest.NewRequest("POST", "/cache-insert", strings.NewReader(body))
	w := httptest.NewRecorder()

	proxy.cacheInsertHandler(w, req)

	if w.Code != 502 {
		t.Fatalf("expected 502 for IPC failure, got %d", w.Code)
	}
}

func TestCacheInsertHandler_NoEnclaveClient(t *testing.T) {
	proxy := &odohProxy{enclaveEnabled: false, enclaveClient: nil}

	body := `{"encrypted_blob":"AQIDBA==","signature":"BQYHCA=="}`
	req := httptest.NewRequest("POST", "/cache-insert", strings.NewReader(body))
	w := httptest.NewRecorder()

	proxy.cacheInsertHandler(w, req)

	if w.Code != 502 {
		t.Fatalf("expected 502 when enclave not configured, got %d", w.Code)
	}
}

func TestCacheInsertHandler_MethodNotAllowed(t *testing.T) {
	proxy := &odohProxy{}

	req := httptest.NewRequest("GET", "/cache-insert", nil)
	w := httptest.NewRecorder()

	proxy.cacheInsertHandler(w, req)

	if w.Code != 405 {
		t.Fatalf("expected 405 for GET, got %d", w.Code)
	}
}

func TestMain(m *testing.M) {
	// Suppress log output during tests
	os.Exit(m.Run())
}
