package enclave

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// CacheInsertBundle is the plaintext inside the HPKE-encrypted cache-insert blob.
// Sent by the target, encrypted to pk_E, signed with Ed25519.
type CacheInsertBundle struct {
	TTL            uint32 // seconds
	Timestamp      int64  // unix seconds
	CanonicalQuery string // e.g. "example.com.:1"
	DNSResponse    []byte // raw DNS wire format
}

// MarshalCacheInsertBundle serializes a CacheInsertBundle.
// Format: ttl(4) || timestamp(8) || query_len(2) || canonical_query || dns_response
func MarshalCacheInsertBundle(b *CacheInsertBundle) []byte {
	queryBytes := []byte(b.CanonicalQuery)
	size := 4 + 8 + 2 + len(queryBytes) + len(b.DNSResponse)
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], b.TTL)
	offset += 4

	binary.BigEndian.PutUint64(buf[offset:], uint64(b.Timestamp))
	offset += 8

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(queryBytes)))
	offset += 2

	copy(buf[offset:], queryBytes)
	offset += len(queryBytes)

	copy(buf[offset:], b.DNSResponse)
	return buf
}

// ParseCacheInsertBundle deserializes a CacheInsertBundle.
func ParseCacheInsertBundle(data []byte) (*CacheInsertBundle, error) {
	if len(data) < 14 { // 4 + 8 + 2 minimum
		return nil, errors.New("bundle too short")
	}

	offset := 0

	ttl := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	timestamp := int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	queryLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if offset+int(queryLen) > len(data) {
		return nil, fmt.Errorf("query_len %d exceeds data", queryLen)
	}

	query := string(data[offset : offset+int(queryLen)])
	offset += int(queryLen)

	dnsResponse := data[offset:]

	return &CacheInsertBundle{
		TTL:            ttl,
		Timestamp:      timestamp,
		CanonicalQuery: query,
		DNSResponse:    dnsResponse,
	}, nil
}
