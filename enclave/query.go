package enclave

import (
	"strconv"
	"strings"
)

// CanonicalizeQuery creates a canonical cache key from a DNS query.
// Format: "lowercased.fqdn.:TYPE"
// Example: "EXAMPLE.COM" + A -> "example.com.:1"
func CanonicalizeQuery(domain string, qtype uint16) string {
	// Lowercase
	domain = strings.ToLower(domain)

	// Ensure trailing dot (FQDN)
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	// Append query type as number
	return domain + ":" + strconv.FormatUint(uint64(qtype), 10)
}

// ParseCanonicalQuery extracts domain and qtype from a canonical query string.
// Returns domain (without trailing dot) and qtype.
func ParseCanonicalQuery(canonical string) (string, uint16, bool) {
	idx := strings.LastIndex(canonical, ":")
	if idx < 0 {
		return "", 0, false
	}

	domain := canonical[:idx]
	qtypeStr := canonical[idx+1:]

	// Remove trailing dot from domain
	domain = strings.TrimSuffix(domain, ".")

	// Parse qtype
	qtype, err := strconv.ParseUint(qtypeStr, 10, 16)
	if err != nil {
		return "", 0, false
	}

	return domain, uint16(qtype), true
}

// Common DNS query types for reference
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
)
