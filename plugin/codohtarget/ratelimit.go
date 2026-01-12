// Package codohtarget implements per-prefix rate limiting for token issuance.
package codohtarget

import (
	"net"
	"sync"
)

// rateLimiter tracks token issuance per IP prefix.
type rateLimiter struct {
	counts map[string]int // prefix -> count
	limit  int            // max tokens per prefix per epoch
	epoch  uint32         // current epoch (reset on change)
	mu     sync.Mutex
}

// newRateLimiter creates a new rate limiter with the given limit.
func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{
		counts: make(map[string]int),
		limit:  limit,
	}
}

// allow checks if count tokens can be issued for the given IP.
// Returns true if allowed and increments the counter.
func (r *rateLimiter) allow(ip net.IP, count int, epoch uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset on epoch change
	if epoch != r.epoch {
		r.counts = make(map[string]int)
		r.epoch = epoch
	}

	prefix := r.ipPrefix(ip)
	current := r.counts[prefix]

	if current+count > r.limit {
		return false
	}

	r.counts[prefix] = current + count
	return true
}

// remaining returns how many tokens the IP prefix can still request.
func (r *rateLimiter) remaining(ip net.IP, epoch uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset on epoch change
	if epoch != r.epoch {
		r.counts = make(map[string]int)
		r.epoch = epoch
	}

	prefix := r.ipPrefix(ip)
	current := r.counts[prefix]
	remaining := r.limit - current
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ipPrefix extracts the rate-limiting prefix from an IP.
// IPv4: /24, IPv6: /48
func (r *rateLimiter) ipPrefix(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: /24 prefix
		return ip4.Mask(net.CIDRMask(24, 32)).String()
	}
	// IPv6: /48 prefix
	return ip.Mask(net.CIDRMask(48, 128)).String()
}
