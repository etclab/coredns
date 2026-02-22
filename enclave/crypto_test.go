package enclave

import (
	"bytes"
	"sort"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestHPKEExport(t *testing.T) {
	kemID := hpke.KEM_X25519_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES128GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("codoh-enclave-v2")

	// Generate receiver keypair
	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Sender side: encrypt a query
	sender, err := suite.NewSender(pub, info)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	enc, sealer, err := sender.Setup(nil)
	if err != nil {
		t.Fatalf("sender.Setup: %v", err)
	}

	query := []byte("example.com.:1")
	ct, err := sealer.Seal(query, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Derive k_r from sender context
	exportLabel := []byte("codoh response")
	senderKr := sealer.Export(exportLabel, 16)

	// Receiver side: decrypt the query
	receiver, err := suite.NewReceiver(priv, info)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatalf("receiver.Setup: %v", err)
	}

	pt, err := opener.Open(ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(pt, query) {
		t.Fatalf("decrypted query mismatch: got %q, want %q", pt, query)
	}

	// Derive k_r from receiver context
	receiverKr := opener.Export(exportLabel, 16)

	// Both sides must derive identical k_r
	if !bytes.Equal(senderKr, receiverKr) {
		t.Fatalf("Export mismatch:\n  sender:   %x\n  receiver: %x", senderKr, receiverKr)
	}

	if len(senderKr) != 16 {
		t.Fatalf("k_r length: got %d, want 16", len(senderKr))
	}

	t.Logf("k_r (16 bytes): %x", senderKr)
}

func TestHPKEExportDifferentSessions(t *testing.T) {
	kemID := hpke.KEM_X25519_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES128GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("codoh-enclave-v2")

	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	exportLabel := []byte("codoh response")

	// Session 1
	sender1, _ := suite.NewSender(pub, info)
	enc1, sealer1, _ := sender1.Setup(nil)
	kr1 := sealer1.Export(exportLabel, 16)

	receiver1, _ := suite.NewReceiver(priv, info)
	opener1, _ := receiver1.Setup(enc1)
	kr1r := opener1.Export(exportLabel, 16)

	// Session 2 (same keypair, different ephemeral)
	sender2, _ := suite.NewSender(pub, info)
	enc2, sealer2, _ := sender2.Setup(nil)
	kr2 := sealer2.Export(exportLabel, 16)

	receiver2, _ := suite.NewReceiver(priv, info)
	opener2, _ := receiver2.Setup(enc2)
	kr2r := opener2.Export(exportLabel, 16)

	// Each session's sender/receiver must match
	if !bytes.Equal(kr1, kr1r) {
		t.Fatal("session 1 sender/receiver k_r mismatch")
	}
	if !bytes.Equal(kr2, kr2r) {
		t.Fatal("session 2 sender/receiver k_r mismatch")
	}

	// Different sessions must produce different k_r
	if bytes.Equal(kr1, kr2) {
		t.Fatal("different sessions produced identical k_r — ephemeral randomness not working")
	}
}

func TestDecryptQueryE(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Simulate client-side encryption (sender)
	sender, err := suite.NewSender(kp.PublicKey, info)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	enc, sealer, err := sender.Setup(nil)
	if err != nil {
		t.Fatalf("sender.Setup: %v", err)
	}

	query := []byte("example.com.:1")
	ct, err := sealer.Seal(query, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	senderKr := sealer.Export(ExportLabel, ExportKeyLen)

	// Build Q_E: enc || ciphertext
	qe := make([]byte, len(enc)+len(ct))
	copy(qe, enc)
	copy(qe[len(enc):], ct)

	// Enclave decrypts
	gotQuery, gotKr, err := kp.DecryptQueryE(qe)
	if err != nil {
		t.Fatalf("DecryptQueryE: %v", err)
	}

	if !bytes.Equal(gotQuery, query) {
		t.Fatalf("query mismatch: got %q, want %q", gotQuery, query)
	}

	if !bytes.Equal(gotKr, senderKr) {
		t.Fatalf("k_r mismatch:\n  sender:   %x\n  enclave:  %x", senderKr, gotKr)
	}
}

func TestDecryptQueryE_WrongKey(t *testing.T) {
	kp1, _ := GenerateKeypair()
	kp2, _ := GenerateKeypair()

	// Encrypt to kp1's public key
	sender, _ := suite.NewSender(kp1.PublicKey, info)
	enc, sealer, _ := sender.Setup(nil)
	ct, _ := sealer.Seal([]byte("test"), nil)

	qe := make([]byte, len(enc)+len(ct))
	copy(qe, enc)
	copy(qe[len(enc):], ct)

	// Try to decrypt with kp2's private key — should fail
	_, _, err := kp2.DecryptQueryE(qe)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEncryptCachedResponse(t *testing.T) {
	kr := make([]byte, 16)
	kr[0] = 0xAB // non-zero key

	response := []byte("dns response bytes here")

	ct1, err := EncryptCachedResponse(kr, response)
	if err != nil {
		t.Fatalf("EncryptCachedResponse: %v", err)
	}

	ct2, err := EncryptCachedResponse(kr, response)
	if err != nil {
		t.Fatalf("EncryptCachedResponse (2nd): %v", err)
	}

	// Two encryptions of same plaintext must produce different ciphertexts (random nonce)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions produced identical ciphertext — nonce not random")
	}

	// Verify format: nonce(12) || ciphertext(len + 16 tag)
	expectedLen := 12 + len(response) + 16
	if len(ct1) != expectedLen {
		t.Fatalf("ciphertext length: got %d, want %d", len(ct1), expectedLen)
	}
}

func TestEncryptDecryptCachedResponse_RoundTrip(t *testing.T) {
	kp, _ := GenerateKeypair()

	// Simulate full flow: client encrypts Q_E, enclave decrypts, both derive k_r
	sender, _ := suite.NewSender(kp.PublicKey, info)
	enc, sealer, _ := sender.Setup(nil)
	query := []byte("example.com.:1")
	ct, _ := sealer.Seal(query, nil)
	senderKr := sealer.Export(ExportLabel, ExportKeyLen)

	qe := make([]byte, len(enc)+len(ct))
	copy(qe, enc)
	copy(qe[len(enc):], ct)

	_, enclaveKr, _ := kp.DecryptQueryE(qe)

	// Enclave encrypts a cached response
	dnsResponse := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	encrypted, err := EncryptCachedResponse(enclaveKr, dnsResponse)
	if err != nil {
		t.Fatalf("EncryptCachedResponse: %v", err)
	}

	// Client decrypts using sender-side k_r
	decrypted, err := DecryptCachedResponse(senderKr, encrypted)
	if err != nil {
		t.Fatalf("DecryptCachedResponse: %v", err)
	}

	if !bytes.Equal(decrypted, dnsResponse) {
		t.Fatalf("round-trip mismatch: got %x, want %x", decrypted, dnsResponse)
	}
}

func TestDecryptCachedResponse_DummyFails(t *testing.T) {
	kr := make([]byte, 16)
	kr[0] = 0xAB

	dummy := GenerateDummyResponse(512)

	_, err := DecryptCachedResponse(kr, dummy)
	if err == nil {
		t.Fatal("expected AEAD auth failure on dummy response")
	}
}

func TestEncryptQueryE_FullFlow(t *testing.T) {
	kp, _ := GenerateKeypair()

	query := []byte("example.com.:1")

	// Client encrypts Q_E using the public API
	qe, clientKr, err := EncryptQueryE(kp.PublicKey, query)
	if err != nil {
		t.Fatalf("EncryptQueryE: %v", err)
	}

	// Enclave decrypts
	gotQuery, enclaveKr, err := kp.DecryptQueryE(qe)
	if err != nil {
		t.Fatalf("DecryptQueryE: %v", err)
	}

	if !bytes.Equal(gotQuery, query) {
		t.Fatalf("query mismatch: got %q, want %q", gotQuery, query)
	}
	if !bytes.Equal(clientKr, enclaveKr) {
		t.Fatalf("k_r mismatch:\n  client:  %x\n  enclave: %x", clientKr, enclaveKr)
	}

	// Enclave encrypts response, client decrypts
	dnsResp := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encrypted, _ := EncryptCachedResponse(enclaveKr, dnsResp)
	decrypted, err := DecryptCachedResponse(clientKr, encrypted)
	if err != nil {
		t.Fatalf("DecryptCachedResponse: %v", err)
	}
	if !bytes.Equal(decrypted, dnsResp) {
		t.Fatalf("response mismatch: got %x, want %x", decrypted, dnsResp)
	}
}

func TestGenerateDummyResponse(t *testing.T) {
	d1 := GenerateDummyResponse(512)
	d2 := GenerateDummyResponse(512)

	if len(d1) != 512 {
		t.Fatalf("dummy size: got %d, want 512", len(d1))
	}

	if bytes.Equal(d1, d2) {
		t.Fatal("two dummy responses are identical — randomness broken")
	}
}

// --- Sprint 6: Bucketed Padding Tests ---

func TestPadToBucket_RoundTrip(t *testing.T) {
	buckets := []int{1024, 2048, 4096, 8192, 16384}
	testData := [][]byte{
		[]byte("hello"),
		make([]byte, 100),
		make([]byte, 1000),
		make([]byte, 4000),
		make([]byte, 8000),
	}
	for _, data := range testData {
		padded, err := PadToBucket(data, buckets)
		if err != nil {
			t.Fatalf("PadToBucket(%d bytes): %v", len(data), err)
		}
		unpadded, err := UnpadFromBucket(padded)
		if err != nil {
			t.Fatalf("UnpadFromBucket: %v", err)
		}
		if !bytes.Equal(unpadded, data) {
			t.Fatalf("round-trip failed for %d-byte data: got %d bytes", len(data), len(unpadded))
		}
	}
}

func TestPadToBucket_OutputLengthInBucketSet(t *testing.T) {
	buckets := []int{1024, 2048, 4096, 8192, 16384}
	sorted := make([]int, len(buckets))
	copy(sorted, buckets)
	sort.Ints(sorted)

	for dataLen := 1; dataLen <= 16000; dataLen += 137 {
		data := make([]byte, dataLen)
		padded, err := PadToBucket(data, buckets)
		if err != nil {
			t.Fatalf("PadToBucket(%d bytes): %v", dataLen, err)
		}
		found := false
		for _, b := range sorted {
			if len(padded) == b {
				found = true
				break
			}
		}
		if !found {
			// Check if it's a valid multiple of the largest bucket
			largest := sorted[len(sorted)-1]
			if len(padded)%largest != 0 {
				t.Fatalf("data=%d: padded len=%d not in bucket set and not a multiple of %d",
					dataLen, len(padded), largest)
			}
		}
	}
}

func TestPadToBucket_EncryptedResponsePads(t *testing.T) {
	kr := make([]byte, 16)
	kr[0] = 0xAB
	response := []byte("short DNS response")

	encrypted, err := EncryptCachedResponse(kr, response)
	if err != nil {
		t.Fatalf("EncryptCachedResponse: %v", err)
	}

	padded, err := PadToBucket(encrypted, DefaultPadBuckets)
	if err != nil {
		t.Fatalf("PadToBucket: %v", err)
	}

	if len(padded) != DefaultPadBuckets[0] {
		t.Fatalf("padded len=%d, want %d", len(padded), DefaultPadBuckets[0])
	}

	// Verify round-trip: unpad → decrypt
	unpadded, err := UnpadFromBucket(padded)
	if err != nil {
		t.Fatalf("UnpadFromBucket: %v", err)
	}
	decrypted, err := DecryptCachedResponse(kr, unpadded)
	if err != nil {
		t.Fatalf("DecryptCachedResponse: %v", err)
	}
	if !bytes.Equal(decrypted, response) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, response)
	}
}

func TestPadToBucket_ExceedsLargestBucket(t *testing.T) {
	buckets := []int{1024, 2048}
	// Data that needs 2050 bytes (data + 2-byte prefix) > 2048
	data := make([]byte, 2048)
	padded, err := PadToBucket(data, buckets)
	if err != nil {
		t.Fatalf("PadToBucket: %v", err)
	}
	// Should round up to next multiple of 2048 = 4096
	if len(padded) != 4096 {
		t.Fatalf("padded len=%d, want 4096 (2*largest bucket)", len(padded))
	}
	// Still round-trips
	unpadded, err := UnpadFromBucket(padded)
	if err != nil {
		t.Fatalf("UnpadFromBucket: %v", err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Fatal("round-trip failed for oversized data")
	}
}

func TestPadToBucket_RandomFill(t *testing.T) {
	data := []byte("same data")
	p1, _ := PadToBucket(data, DefaultPadBuckets)
	p2, _ := PadToBucket(data, DefaultPadBuckets)

	// The data portion is identical but padding bytes should differ (with overwhelming probability)
	if bytes.Equal(p1, p2) {
		t.Fatal("two paddings of same data are identical — random fill not working")
	}
	// But unpadded data should match
	u1, _ := UnpadFromBucket(p1)
	u2, _ := UnpadFromBucket(p2)
	if !bytes.Equal(u1, u2) {
		t.Fatal("unpadded data should be identical")
	}
}

func TestUnpadFromBucket_Errors(t *testing.T) {
	// Too short
	_, err := UnpadFromBucket([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for 1-byte input")
	}

	// Invalid length prefix (claims 1000 bytes but only 10 available)
	bad := make([]byte, 10)
	bad[0] = 0xE8 // 1000 in LE
	bad[1] = 0x03
	_, err = UnpadFromBucket(bad)
	if err == nil {
		t.Fatal("expected error for invalid length prefix")
	}

	// Empty input
	_, err = UnpadFromBucket(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}
