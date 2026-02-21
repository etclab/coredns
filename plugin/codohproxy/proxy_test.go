package codohproxy

import (
	"bytes"
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

// mockEnclaveHandler implements enclave.RequestHandler for testing.
type mockEnclaveHandler struct {
	processFunc        func(qe string) *enclave.Response
	storeEncryptedFunc func(blob, sig string) *enclave.Response

	// Captured store_encrypted calls
	mu         sync.Mutex
	storeCalls []storeCall
}

type storeCall struct {
	Blob string
	Sig  string
}

func (m *mockEnclaveHandler) HandleProcess(qe string) *enclave.Response {
	return m.processFunc(qe)
}

func (m *mockEnclaveHandler) HandleStoreEncrypted(blob, sig string) *enclave.Response {
	m.mu.Lock()
	m.storeCalls = append(m.storeCalls, storeCall{Blob: blob, Sig: sig})
	m.mu.Unlock()
	if m.storeEncryptedFunc != nil {
		return m.storeEncryptedFunc(blob, sig)
	}
	return &enclave.Response{Status: enclave.StatusOK}
}

func (m *mockEnclaveHandler) HandleGetPubKey() *enclave.Response {
	return &enclave.Response{Status: enclave.StatusOK, PubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
}

func (m *mockEnclaveHandler) HandleHealth() *enclave.Response {
	return &enclave.Response{Status: enclave.StatusOK}
}

func TestProxyHandler_KeyRotated(t *testing.T) {
	// 1. Start mock enclave on temp Unix socket using the real IPC server.
	socketPath := filepath.Join(t.TempDir(), "test-enclave.sock")
	handler := &mockEnclaveHandler{
		processFunc: func(qe string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusKeyRotated}
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
	// Verify that a normal cache miss (status:"miss" with dummy blob) produces
	// a two-chunk response with application/codoh-response content type.
	socketPath := filepath.Join(t.TempDir(), "test-enclave.sock")
	dummyBlob := "AQIDBA==" // base64 of {0x01, 0x02, 0x03, 0x04}
	handler := &mockEnclaveHandler{
		processFunc: func(qe string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusMiss, Response: dummyBlob}
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

	// Two-chunk format: [2-byte len][chunk1][chunk2]
	if len(body) < 2 {
		t.Fatalf("body too short: %d bytes", len(body))
	}
	chunk1Len := int(body[0])<<8 | int(body[1])
	if 2+chunk1Len > len(body) {
		t.Fatalf("chunk1 len %d exceeds body (%d bytes)", chunk1Len, len(body)-2)
	}
	chunk1 := body[2 : 2+chunk1Len]
	chunk2 := body[2+chunk1Len:]

	expectedChunk1 := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(chunk1, expectedChunk1) {
		t.Fatalf("chunk1 mismatch: got %x, want %x", chunk1, expectedChunk1)
	}
	if !bytes.Equal(chunk2, targetBody) {
		t.Fatalf("chunk2 mismatch: got %x, want %x", chunk2, targetBody)
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
		processFunc: func(qe string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusMiss}
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

	// Verify enclave received the store_encrypted call with correct values
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.storeCalls) != 1 {
		t.Fatalf("expected 1 store call, got %d", len(handler.storeCalls))
	}
	if handler.storeCalls[0].Blob != "AQIDBA==" {
		t.Errorf("blob mismatch: got %q", handler.storeCalls[0].Blob)
	}
	if handler.storeCalls[0].Sig != "BQYHCA==" {
		t.Errorf("sig mismatch: got %q", handler.storeCalls[0].Sig)
	}
}

func TestCacheInsertHandler_InvalidJSON(t *testing.T) {
	handler := &mockEnclaveHandler{
		processFunc: func(qe string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusMiss}
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
		processFunc: func(qe string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusMiss}
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
		processFunc: func(qe string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusMiss}
		},
		storeEncryptedFunc: func(blob, sig string) *enclave.Response {
			return &enclave.Response{Status: enclave.StatusError, Error: "decrypt_failed"}
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
