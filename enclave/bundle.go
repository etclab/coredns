package enclave

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// CacheInsertBundle is the plaintext inside the HPKE-encrypted cache-insert blob.
// Sent by the target, encrypted to pk_E, signed with Ed25519.
type CacheInsertBundle struct {
	TTL            uint32 // seconds
	Timestamp      int64  // unix seconds
	CanonicalQuery string // e.g. "example.com.:1"
	DNSResponse    []byte // raw DNS wire format
}

// marshalEntry serializes a single CacheInsertBundle entry.
// Format: ttl(4) || timestamp(8) || query_len(2) || canonical_query || dns_response
func marshalEntry(b *CacheInsertBundle) []byte {
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

// parseEntry deserializes a single CacheInsertBundle entry.
func parseEntry(data []byte) (*CacheInsertBundle, error) {
	if len(data) < 14 { // 4 + 8 + 2 minimum
		return nil, errors.New("entry too short")
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

	dnsResponse := make([]byte, len(data[offset:]))
	copy(dnsResponse, data[offset:])

	return &CacheInsertBundle{
		TTL:            ttl,
		Timestamp:      timestamp,
		CanonicalQuery: query,
		DNSResponse:    dnsResponse,
	}, nil
}

// MarshalCacheInsertBundle serializes a single CacheInsertBundle.
// Deprecated: use MarshalMultiBundle for the multi-entry wire format.
func MarshalCacheInsertBundle(b *CacheInsertBundle) []byte {
	return marshalEntry(b)
}

// ParseCacheInsertBundle deserializes a single CacheInsertBundle.
// Deprecated: use ParseMultiBundle for the multi-entry wire format.
func ParseCacheInsertBundle(data []byte) (*CacheInsertBundle, error) {
	return parseEntry(data)
}

// CanonicalizeQuery produces the canonical cache key for a DNS query.
// Format: "example.com.:1" (lowercase FQDN with trailing dot, colon, qtype).
func CanonicalizeQuery(domain string, qtype uint16) string {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	return fmt.Sprintf("%s.:%d", d, qtype)
}

// MarshalMultiBundle serializes multiple CacheInsertBundle entries into the
// multi-entry wire format:
//
//	count(2) || for each entry: entry_len(4) || entry_data
//
// count must be >= 1. Even k=0 (no covers) produces a multi-bundle with count=1.
func MarshalMultiBundle(entries []CacheInsertBundle) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("multi-bundle: count must be >= 1")
	}
	if len(entries) > 65535 {
		return nil, errors.New("multi-bundle: too many entries")
	}

	// Pre-serialize all entries to calculate total size
	serialized := make([][]byte, len(entries))
	totalSize := 2 // count field
	for i := range entries {
		serialized[i] = marshalEntry(&entries[i])
		totalSize += 4 + len(serialized[i]) // entry_len + entry_data
	}

	buf := make([]byte, totalSize)
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(entries)))
	offset += 2

	for _, entry := range serialized {
		binary.BigEndian.PutUint32(buf[offset:], uint32(len(entry)))
		offset += 4
		copy(buf[offset:], entry)
		offset += len(entry)
	}

	return buf, nil
}

// ParseMultiBundle deserializes the multi-entry wire format into a slice
// of CacheInsertBundle.
func ParseMultiBundle(data []byte) ([]CacheInsertBundle, error) {
	if len(data) < 2 {
		return nil, errors.New("multi-bundle: data too short")
	}

	count := binary.BigEndian.Uint16(data[:2])
	if count == 0 {
		return nil, errors.New("multi-bundle: count is 0")
	}

	offset := 2
	entries := make([]CacheInsertBundle, 0, count)

	for i := 0; i < int(count); i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("multi-bundle: truncated at entry %d length", i)
		}
		entryLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if offset+int(entryLen) > len(data) {
			return nil, fmt.Errorf("multi-bundle: truncated at entry %d data", i)
		}

		entry, err := parseEntry(data[offset : offset+int(entryLen)])
		if err != nil {
			return nil, fmt.Errorf("multi-bundle: entry %d: %w", i, err)
		}
		entries = append(entries, *entry)
		offset += int(entryLen)
	}

	return entries, nil
}
