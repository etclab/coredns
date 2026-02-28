package cover

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MaxNegativeTTL caps negative-cache TTLs for cover responses (enclave-defined upper bound).
const MaxNegativeTTL uint32 = 3600 // 1 hour

// ResolvedCover holds a successfully resolved cover domain.
type ResolvedCover struct {
	Domain      string
	DNSResponse []byte // wire-format DNS response
	TTL         uint32 // from DNS response; RFC 2308 SOA-derived for NXDOMAIN
}

// Resolver performs parallel DNS resolution for cover domains.
type Resolver struct {
	address string
	timeout time.Duration
	client  *dns.Client
}

// NewResolver creates a Resolver targeting the given DNS server address.
func NewResolver(address string, timeout time.Duration) *Resolver {
	return &Resolver{
		address: address,
		timeout: timeout,
		client:  &dns.Client{Timeout: timeout},
	}
}

// Resolve resolves all domains in parallel (A records only).
// Returns only successful results, including NXDOMAIN/SERVFAIL responses.
// Network errors and timeouts are silently dropped.
func (r *Resolver) Resolve(ctx context.Context, domains []string) []ResolvedCover {
	var (
		mu      sync.Mutex
		results []ResolvedCover
		wg      sync.WaitGroup
	)

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(d), dns.TypeA)

			resp, _, err := r.client.ExchangeContext(ctx, m, r.address)
			if err != nil {
				return // network error / timeout — drop
			}

			wireResp, err := resp.Pack()
			if err != nil {
				return
			}

			ttl := extractCoverTTL(resp)

			mu.Lock()
			results = append(results, ResolvedCover{
				Domain:      d,
				DNSResponse: wireResp,
				TTL:         ttl,
			})
			mu.Unlock()
		}(domain)
	}

	wg.Wait()
	return results
}

// extractCoverTTL derives the TTL for a cover response.
// For positive responses: uses the first Answer RR's TTL.
// For NXDOMAIN/NODATA: applies RFC 2308 negative caching — min(SOA.Ttl, SOA.Minttl),
// capped by MaxNegativeTTL (enclave-defined upper bound per paper spec).
// For SERVFAIL or other errors: uses MaxNegativeTTL as a reasonable default.
func extractCoverTTL(resp *dns.Msg) uint32 {
	// Positive response — use first answer TTL
	for _, rr := range resp.Answer {
		if rr.Header().Ttl > 0 {
			return rr.Header().Ttl
		}
	}

	// Negative response (NXDOMAIN or NODATA) — derive from SOA per RFC 2308
	if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
		for _, rr := range resp.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl := soa.Hdr.Ttl
				if soa.Minttl < ttl {
					ttl = soa.Minttl
				}
				if ttl > MaxNegativeTTL {
					ttl = MaxNegativeTTL
				}
				return ttl
			}
		}
	}

	// No SOA found or SERVFAIL — use upper bound
	return MaxNegativeTTL
}
