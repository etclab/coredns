package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/coredns/coredns/enclave"
)

// ipcRoundTrip sends a binary IPC request and reads the response.
func ipcRoundTrip(conn net.Conn, msgType byte, payload []byte) (byte, []byte, error) {
	totalLen := uint32(1 + len(payload))
	if err := binary.Write(conn, binary.BigEndian, totalLen); err != nil {
		return 0, nil, err
	}
	if _, err := conn.Write([]byte{msgType}); err != nil {
		return 0, nil, err
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return 0, nil, err
		}
	}

	var respLen uint32
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		return 0, nil, err
	}
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func startIPCServer(b *testing.B, h enclave.RequestHandler, name string) (net.Conn, func()) {
	b.Helper()
	socketPath := filepath.Join(os.TempDir(), "bench-ipc-"+name+".sock")
	os.Remove(socketPath)

	server, err := enclave.NewIPCServer(socketPath, h)
	if err != nil {
		b.Fatal(err)
	}
	go server.Serve()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		server.Close()
		b.Fatal(err)
	}

	cleanup := func() {
		conn.Close()
		server.Close()
		os.Remove(socketPath)
	}
	return conn, cleanup
}

func BenchmarkIPC_HealthCheck(b *testing.B) {
	h := newTestHandler(3.0)
	conn, cleanup := startIPCServer(b, h, "health")
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status, _, err := ipcRoundTrip(conn, enclave.BinMsgHealth, nil)
		if err != nil {
			b.Fatal(err)
		}
		if status != enclave.BinStatusOK {
			b.Fatalf("health check failed: 0x%02x", status)
		}
	}
}

func BenchmarkIPC_CacheHit(b *testing.B) {
	h := newTestHandler(3.0)
	h.tLatest.Store(1000)
	h.cache.Put("bench.com.:1", []byte{0xDE, 0xAD, 0xBE, 0xEF}, 1000, 3600)

	// Build padded Q_E for the cached entry
	pubBytes, _ := h.keypair.PublicKeyBytes()
	pk, err := enclave.ParsePublicKeyBytes(pubBytes)
	if err != nil {
		b.Fatal(err)
	}
	qeRaw, _, err := enclave.EncryptQueryE(pk, []byte("bench.com.:1"))
	if err != nil {
		b.Fatal(err)
	}
	qePadded, err := enclave.PadToBucket(qeRaw, []int{256})
	if err != nil {
		b.Fatal(err)
	}

	conn, cleanup := startIPCServer(b, h, "cachehit")
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status, _, err := ipcRoundTrip(conn, enclave.BinMsgProcess, qePadded)
		if err != nil {
			b.Fatal(err)
		}
		if status != enclave.BinStatusProcessed {
			b.Fatalf("cache hit failed: 0x%02x", status)
		}
	}
}