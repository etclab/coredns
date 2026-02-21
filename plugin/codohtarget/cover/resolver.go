package cover

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResolvedCover holds a successfully resolved cover domain.
type ResolvedCover struct {
	Domain      string
	DNSResponse []byte // wire-format DNS response
	TTL         uint32 // from DNS response, or MaxUint32 for NXDOMAIN/SERVFAIL
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

			var ttl uint32
			for _, rr := range resp.Answer {
				if rr.Header().Ttl > 0 {
					ttl = rr.Header().Ttl
					break
				}
			}
			// Covers with no TTL (NXDOMAIN/SERVFAIL) persist until LRU eviction.
			// They exist purely for G2 (cache-state indistinguishability).
			if ttl == 0 {
				ttl = math.MaxUint32
			}

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
