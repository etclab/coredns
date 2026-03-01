// analyze-padding.go — Analyze DNS query and response sizes to determine optimal padding buckets.
//
// Usage: go run benchmark/analyze-padding.go [-domains benchmark/top-1k-resolvable.csv] [-workers 50]
//
// Resolves each domain (A record) and reports:
//   - Raw DNS query wire sizes (what goes into Q_T)
//   - Q_E plaintext sizes: 32B (kc) + len(CanonicalizeQuery)
//   - Q_E ciphertext sizes: 32B (HPKE enc) + plaintext + 16B (GCM tag)
//   - Q_T ciphertext sizes: ODoH overhead around raw DNS query
//   - Response wire sizes
//   - Suggested bucket sizes (power-of-2 and percentile-based)
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// HPKE overhead constants (DHKEM X25519 + AES-128-GCM)
const (
	hpkeEncSize = 32 // X25519 public key (enc)
	hpkeTagSize = 16 // AES-128-GCM tag
	kcSize      = 32 // cache key size in Q_E plaintext
	padPrefix   = 2  // 2-byte LE length prefix for PadToBucket
)

type result struct {
	domain       string
	rawQuerySize int // DNS wire query
	qePlainSize  int // kc + canonicalized query
	qeCipherSize int // hpkeEnc + qePlain + hpkeTag
	qtCipherSize int // ODoH: hpkeEnc + 2B msgType + rawQuery + hpkeTag (+ 2B padding length)
	responseSize int // DNS wire response
	err          error
}

func canonicalizeQuery(domain string, qtype uint16) string {
	d := strings.ToLower(strings.TrimRight(domain, "."))
	return fmt.Sprintf("%s.:%d", d, qtype)
}

func resolve(domain string, server string, timeout time.Duration) result {
	r := result{domain: domain}

	// Build query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	packed, err := msg.Pack()
	if err != nil {
		r.err = fmt.Errorf("pack: %w", err)
		return r
	}
	r.rawQuerySize = len(packed)

	// Q_E plaintext = kc (32B) || CanonicalizeQuery(domain, A)
	canon := canonicalizeQuery(domain, dns.TypeA)
	r.qePlainSize = kcSize + len(canon)

	// Q_E ciphertext = enc (32B) || Seal(plaintext) where Seal adds 16B tag
	r.qeCipherSize = hpkeEncSize + r.qePlainSize + hpkeTagSize

	// Q_T ciphertext ≈ ODoH format: enc (32B) + 2B msg_type + rawQuery + 16B tag + 2B padding_length
	// (ObliviousDoHMessagePlaintext: msg_type(2) + key_id(0 for query) + dns_msg)
	r.qtCipherSize = hpkeEncSize + 2 + r.rawQuerySize + hpkeTagSize + 2

	// Actually resolve to get response size
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout
	resp, _, err := c.Exchange(msg, server)
	if err != nil {
		// Try TCP
		c.Net = "tcp"
		resp, _, err = c.Exchange(msg, server)
		if err != nil {
			r.err = fmt.Errorf("resolve: %w", err)
			return r
		}
	}

	if resp != nil {
		respPacked, err := resp.Pack()
		if err == nil {
			r.responseSize = len(respPacked)
		}
	}

	return r
}

type stats struct {
	name   string
	values []int
}

func (s *stats) compute() {
	sort.Ints(s.values)
	n := len(s.values)
	if n == 0 {
		fmt.Printf("\n=== %s: no data ===\n", s.name)
		return
	}

	sum := 0
	for _, v := range s.values {
		sum += v
	}

	fmt.Printf("\n=== %s (n=%d) ===\n", s.name, n)
	fmt.Printf("  Min:    %5d B\n", s.values[0])
	fmt.Printf("  P25:    %5d B\n", s.values[n*25/100])
	fmt.Printf("  P50:    %5d B\n", s.values[n*50/100])
	fmt.Printf("  P75:    %5d B\n", s.values[n*75/100])
	fmt.Printf("  P90:    %5d B\n", s.values[n*90/100])
	fmt.Printf("  P95:    %5d B\n", s.values[n*95/100])
	fmt.Printf("  P99:    %5d B\n", s.values[n*99/100])
	fmt.Printf("  Max:    %5d B\n", s.values[n-1])
	fmt.Printf("  Mean:   %5d B\n", sum/n)
}

// suggestBuckets prints bucket suggestions based on data distribution.
func (s *stats) suggestBuckets() {
	if len(s.values) == 0 {
		return
	}

	n := len(s.values)
	maxVal := s.values[n-1]

	// Option 1: Single bucket (best privacy — all same size)
	single := nextPow2(maxVal + padPrefix)
	fmt.Printf("  Single bucket (max privacy):  [%d]\n", single)

	// Option 2: Power-of-2 buckets covering the range
	minVal := s.values[0] + padPrefix
	var pow2Buckets []int
	b := nextPow2(minVal)
	for b <= single {
		pow2Buckets = append(pow2Buckets, b)
		b *= 2
	}
	if len(pow2Buckets) > 1 {
		fmt.Printf("  Power-of-2 buckets:           %v\n", pow2Buckets)
		printBucketDistribution(s.values, pow2Buckets)
	}

	// Option 3: Percentile-based (P50, P90, P99, max)
	p50 := s.values[n*50/100] + padPrefix
	p90 := s.values[n*90/100] + padPrefix
	p99 := s.values[n*99/100] + padPrefix
	pMax := maxVal + padPrefix
	var percBuckets []int
	seen := map[int]bool{}
	for _, v := range []int{p50, p90, p99, pMax} {
		aligned := nextPow2(v)
		if !seen[aligned] {
			seen[aligned] = true
			percBuckets = append(percBuckets, aligned)
		}
	}
	sort.Ints(percBuckets)
	if len(percBuckets) > 1 {
		fmt.Printf("  Percentile-aligned buckets:   %v\n", percBuckets)
		printBucketDistribution(s.values, percBuckets)
	}

	// Option 4: Tight (64-byte aligned)
	var tight []int
	seen64 := map[int]bool{}
	for _, pct := range []int{50, 75, 90, 99, 100} {
		idx := n * pct / 100
		if idx >= n {
			idx = n - 1
		}
		v := s.values[idx] + padPrefix
		aligned := ((v + 63) / 64) * 64
		if !seen64[aligned] {
			seen64[aligned] = true
			tight = append(tight, aligned)
		}
	}
	sort.Ints(tight)
	if len(tight) > 1 {
		fmt.Printf("  64B-aligned percentile:       %v\n", tight)
		printBucketDistribution(s.values, tight)
	}
}

func printBucketDistribution(values []int, buckets []int) {
	sort.Ints(buckets)
	counts := make([]int, len(buckets)+1) // last = overflow
	totalWaste := 0
	for _, v := range values {
		v += padPrefix
		placed := false
		for i, b := range buckets {
			if v <= b {
				counts[i]++
				totalWaste += b - v
				placed = true
				break
			}
		}
		if !placed {
			counts[len(buckets)]++
		}
	}
	for i, b := range buckets {
		fmt.Printf("    <= %5d B: %5d values (%5.1f%%)\n", b, counts[i], 100*float64(counts[i])/float64(len(values)))
	}
	if counts[len(buckets)] > 0 {
		fmt.Printf("    overflow:   %5d values\n", counts[len(buckets)])
	}
	fmt.Printf("    Avg waste:  %5d B/msg\n", totalWaste/len(values))
}

func nextPow2(v int) int {
	if v <= 0 {
		return 1
	}
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

type wasteResult struct {
	meanSize  int     // mean message size including pad prefix
	meanWaste int     // mean wasted bytes per message
	pct       float64 // waste as % of bucket size
}

func paddingWaste(values []int, bucket int) wasteResult {
	if len(values) == 0 {
		return wasteResult{}
	}
	totalSize := 0
	totalWaste := 0
	for _, v := range values {
		withPrefix := v + padPrefix
		totalSize += withPrefix
		waste := bucket - withPrefix
		if waste < 0 {
			waste = 0
		}
		totalWaste += waste
	}
	n := len(values)
	return wasteResult{
		meanSize:  totalSize / n,
		meanWaste: totalWaste / n,
		pct:       float64(totalWaste) / float64(n) / float64(bucket) * 100,
	}
}

func main() {
	domainFile := flag.String("domains", "benchmark/top-1k-resolvable.csv", "CSV file: rank,domain")
	workers := flag.Int("workers", 50, "concurrent resolvers")
	resolver := flag.String("resolver", "", "DNS resolver (default: system)")
	timeoutSec := flag.Int("timeout", 3, "per-query timeout in seconds")
	verbose := flag.Bool("verbose", false, "show detailed bucket suggestions and entropy analysis")
	flag.Parse()

	// Determine resolver
	server := *resolver
	if server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(conf.Servers) == 0 {
			server = "8.8.8.8:53"
		} else {
			server = net.JoinHostPort(conf.Servers[0], conf.Port)
		}
	} else if !strings.Contains(server, ":") {
		server = server + ":53"
	}
	timeout := time.Duration(*timeoutSec) * time.Second

	// Read domains
	f, err := os.Open(*domainFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", *domainFile, err)
		os.Exit(1)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			domains = append(domains, strings.TrimSpace(parts[1]))
		} else {
			domains = append(domains, parts[0])
		}
	}

	fmt.Printf("Resolving %d domains via %s (workers=%d, timeout=%ds)...\n",
		len(domains), server, *workers, *timeoutSec)

	// Resolve concurrently
	domainCh := make(chan string, *workers)
	resultCh := make(chan result, len(domains))
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range domainCh {
				resultCh <- resolve(d, server, timeout)
			}
		}()
	}

	for _, d := range domains {
		domainCh <- d
	}
	close(domainCh)
	wg.Wait()
	close(resultCh)

	// Collect
	var (
		rawQuery  stats = stats{name: "Raw DNS Query (wire)"}
		qePlain   stats = stats{name: "Q_E Plaintext (kc + canon)"}
		qeCipher  stats = stats{name: "Q_E Ciphertext (HPKE)"}
		qtCipher  stats = stats{name: "Q_T Ciphertext (ODoH)"}
		respSize  stats = stats{name: "DNS Response (wire)"}
		errCount  int
		respCombined stats = stats{name: "Response after HPKE (enc + resp + tag)"}
	)

	for r := range resultCh {
		if r.err != nil {
			errCount++
			if errCount <= 5 {
				fmt.Fprintf(os.Stderr, "  WARN: %s: %v\n", r.domain, r.err)
			}
			continue
		}
		rawQuery.values = append(rawQuery.values, r.rawQuerySize)
		qePlain.values = append(qePlain.values, r.qePlainSize)
		qeCipher.values = append(qeCipher.values, r.qeCipherSize)
		qtCipher.values = append(qtCipher.values, r.qtCipherSize)
		if r.responseSize > 0 {
			respSize.values = append(respSize.values, r.responseSize)
			// Response after HPKE encryption (what actually gets padded)
			respHPKE := hpkeEncSize + r.responseSize + hpkeTagSize
			respCombined.values = append(respCombined.values, respHPKE)
		}
	}

	if errCount > 5 {
		fmt.Fprintf(os.Stderr, "  ... and %d more errors\n", errCount-5)
	}

	// Sort all value slices for percentile computation
	sort.Ints(qeCipher.values)
	sort.Ints(qtCipher.values)
	sort.Ints(respSize.values)
	sort.Ints(respCombined.values)

	nQ := len(qeCipher.values)
	nR := len(respSize.values)

	fmt.Printf("Resolved: %d domains (%d errors)\n\n", nQ, errCount)

	// ── Sizes before padding ──
	fmt.Println("SIZES BEFORE PADDING")
	fmt.Println("────────────────────────────────────────────────────────")
	fmt.Println("                        Min     P50     P99     Max")
	if nQ > 0 {
		fmt.Printf("  Q_E ciphertext:    %5d B  %5d B  %5d B  %5d B\n",
			qeCipher.values[0], qeCipher.values[nQ/2], qeCipher.values[nQ*99/100], qeCipher.values[nQ-1])
		fmt.Printf("  Q_T ciphertext:    %5d B  %5d B  %5d B  %5d B\n",
			qtCipher.values[0], qtCipher.values[nQ/2], qtCipher.values[nQ*99/100], qtCipher.values[nQ-1])
	}
	if nR > 0 {
		fmt.Printf("  DNS response:      %5d B  %5d B  %5d B  %5d B\n",
			respSize.values[0], respSize.values[nR/2], respSize.values[nR*99/100], respSize.values[nR-1])
		fmt.Printf("  Encrypted resp:    %5d B  %5d B  %5d B  %5d B\n",
			respCombined.values[0], respCombined.values[nR/2], respCombined.values[nR*99/100], respCombined.values[nR-1])
	}

	// ── Padding overhead ──
	fmt.Println()
	fmt.Println("PADDING OVERHEAD")
	fmt.Println("────────────────────────────────────────────────────────")
	fmt.Println("Every query is padded to 256 B. Every response is padded to 2048 B.")
	fmt.Println("All messages of each type become the same size (0 bits leaked).")
	fmt.Println()
	fmt.Println("                     Bucket   Mean size   Mean waste   Overhead")
	if nQ > 0 {
		qeWaste := paddingWaste(qeCipher.values, 256)
		qtWaste := paddingWaste(qtCipher.values, 256)
		fmt.Printf("  Q_E (→ enclave):   %5d B   %5d B      %5d B     %4.1f%%\n",
			256, qeWaste.meanSize, qeWaste.meanWaste, qeWaste.pct)
		fmt.Printf("  Q_T (→ target):    %5d B   %5d B      %5d B     %4.1f%%\n",
			256, qtWaste.meanSize, qtWaste.meanWaste, qtWaste.pct)
	}
	if nR > 0 {
		rWaste := paddingWaste(respCombined.values, 2048)
		fmt.Printf("  Response (→ client): %3d B   %5d B      %5d B     %4.1f%%\n",
			2048, rWaste.meanSize, rWaste.meanWaste, rWaste.pct)
	}

	fmt.Println()

	if *verbose {
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("DETAILED ANALYSIS (--verbose)")
		fmt.Println(strings.Repeat("=", 60))

		allStats := []*stats{&rawQuery, &qePlain, &qeCipher, &qtCipher, &respSize, &respCombined}
		for _, s := range allStats {
			s.compute()
		}

		fmt.Println("\n--- Bucket suggestions ---")
		fmt.Println("\nQ_E ciphertext:")
		qeCipher.suggestBuckets()
		fmt.Println("\nQ_T ciphertext:")
		qtCipher.suggestBuckets()
		fmt.Println("\nResponse (HPKE-encrypted):")
		respCombined.suggestBuckets()

		fmt.Println("\n--- Size entropy (bits leaked) ---")
		fmt.Printf("  Q_E unpadded:    %.2f bits\n", sizeEntropy(qeCipher.values))
		fmt.Printf("  Q_E @256B:       %.2f bits\n", sizeEntropy(bucketize(qeCipher.values, []int{256})))
		fmt.Printf("  Resp unpadded:   %.2f bits\n", sizeEntropy(respCombined.values))
		fmt.Printf("  Resp @2048B:     %.2f bits\n", sizeEntropy(bucketize(respCombined.values, []int{2048})))
	}
}

func countUsedBuckets(values []int, buckets []int) int {
	used := map[int]bool{}
	sort.Ints(buckets)
	for _, v := range values {
		v += padPrefix
		for _, b := range buckets {
			if v <= b {
				used[b] = true
				break
			}
		}
	}
	return len(used)
}

func avgWaste(values []int, buckets []int) int {
	if len(values) == 0 {
		return 0
	}
	sort.Ints(buckets)
	total := 0
	for _, v := range values {
		v += padPrefix
		for _, b := range buckets {
			if v <= b {
				total += b - v
				break
			}
		}
	}
	return total / len(values)
}

func bucketize(values []int, buckets []int) []int {
	sort.Ints(buckets)
	out := make([]int, len(values))
	for i, v := range values {
		v += padPrefix
		for _, b := range buckets {
			if v <= b {
				out[i] = b
				break
			}
		}
		if out[i] == 0 {
			largest := buckets[len(buckets)-1]
			out[i] = ((v + largest - 1) / largest) * largest
		}
	}
	return out
}

func sizeEntropy(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	counts := map[int]int{}
	for _, v := range values {
		counts[v]++
	}
	n := float64(len(values))
	entropy := 0.0
	for _, c := range counts {
		p := float64(c) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
