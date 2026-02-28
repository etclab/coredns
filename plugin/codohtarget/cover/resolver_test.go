package cover

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startMockDNS starts a UDP DNS server that responds to A queries.
// handler returns the desired response for each query name.
func startMockDNS(t *testing.T, handler func(name string) *dns.Msg) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := handler(r.Question[0].Name)
		if resp == nil {
			// Simulate timeout by not responding
			return
		}
		resp.SetReply(r)
		w.WriteMsg(resp)
	})}

	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String()
}

func TestResolver_AllSucceed(t *testing.T) {
	addr := startMockDNS(t, func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		})
		return m
	})

	r := NewResolver(addr, 2*time.Second)
	results := r.Resolve(context.Background(), []string{"a.com", "b.com", "c.com"})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for _, rc := range results {
		if len(rc.DNSResponse) == 0 {
			t.Errorf("empty DNS response for %s", rc.Domain)
		}
		if rc.TTL != 300 {
			t.Errorf("TTL for %s: got %d, want 300", rc.Domain, rc.TTL)
		}
	}
}

func TestResolver_TimeoutDropped(t *testing.T) {
	addr := startMockDNS(t, func(name string) *dns.Msg {
		if name == "slow.com." {
			time.Sleep(3 * time.Second) // exceeds 500ms timeout
			return nil
		}
		m := new(dns.Msg)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("5.6.7.8"),
		})
		return m
	})

	r := NewResolver(addr, 500*time.Millisecond)
	results := r.Resolve(context.Background(), []string{"fast1.com", "slow.com", "fast2.com"})

	if len(results) != 2 {
		t.Fatalf("expected 2 results (slow dropped), got %d", len(results))
	}

	for _, rc := range results {
		if rc.Domain == "slow.com" {
			t.Error("slow.com should have been dropped")
		}
	}
}

func TestResolver_NXDOMAINIncluded(t *testing.T) {
	addr := startMockDNS(t, func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		return m
	})

	r := NewResolver(addr, 2*time.Second)
	results := r.Resolve(context.Background(), []string{"nxdomain.com"})

	if len(results) != 1 {
		t.Fatalf("expected 1 result (NXDOMAIN included), got %d", len(results))
	}
	// NXDOMAIN covers without SOA get MaxNegativeTTL (RFC 2308 + upper bound cap).
	if results[0].TTL != MaxNegativeTTL {
		t.Errorf("TTL for NXDOMAIN: got %d, want MaxNegativeTTL (%d)", results[0].TTL, MaxNegativeTTL)
	}
}

func TestResolver_AllFail(t *testing.T) {
	addr := startMockDNS(t, func(name string) *dns.Msg {
		return nil // no response → timeout
	})

	r := NewResolver(addr, 200*time.Millisecond)
	results := r.Resolve(context.Background(), []string{"a.com", "b.com"})

	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}
