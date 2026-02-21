package cover

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
)

// Sampler draws cover domains from a mixture distribution of popular and
// long-tail domains loaded from a Cisco Umbrella Top-1M CSV.
type Sampler struct {
	popular  []string
	longTail []string
	ratio    float64 // probability of sampling from popular
	mu       sync.Mutex
}

// NewSampler loads the domain list from listPath (rank,domain CSV),
// splits at popularCutoff, and uses popularRatio as the coin-flip threshold.
func NewSampler(listPath string, popularCutoff int, popularRatio float64) (*Sampler, error) {
	f, err := os.Open(listPath)
	if err != nil {
		return nil, fmt.Errorf("cover: open domain list: %w", err)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: rank,domain
		if idx := strings.IndexByte(line, ','); idx >= 0 {
			domain := strings.TrimSpace(line[idx+1:])
			if domain != "" {
				domains = append(domains, domain)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cover: read domain list: %w", err)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("cover: domain list is empty")
	}

	s := &Sampler{ratio: popularRatio}
	if popularCutoff >= len(domains) {
		s.popular = domains
	} else {
		s.popular = domains[:popularCutoff]
		s.longTail = domains[popularCutoff:]
	}
	return s, nil
}

// Sample returns up to k unique domains from the mixture distribution,
// excluding the given domain. Thread-safe.
func (s *Sampler) Sample(k int, exclude string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	maxPossible := len(s.popular) + len(s.longTail)
	if exclude != "" {
		maxPossible--
	}
	if k > maxPossible {
		k = maxPossible
	}

	seen := make(map[string]struct{}, k)
	if exclude != "" {
		seen[exclude] = struct{}{}
	}

	result := make([]string, 0, k)
	for len(result) < k {
		var pool []string
		if len(s.longTail) == 0 || cryptoRandFloat64() < s.ratio {
			pool = s.popular
		} else {
			pool = s.longTail
		}
		if len(pool) == 0 {
			continue
		}
		idx := cryptoRandIntn(len(pool))
		domain := pool[idx]
		if _, dup := seen[domain]; dup {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

// cryptoRandFloat64 returns a uniform [0,1) float64 using crypto/rand.
func cryptoRandFloat64() float64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<53))
	return float64(n.Int64()) / float64(1<<53)
}

// cryptoRandIntn returns a uniform random int in [0, n) using crypto/rand.
func cryptoRandIntn(n int) int {
	big, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(big.Int64())
}
