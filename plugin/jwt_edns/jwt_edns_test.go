package jwt_edns

import (
	"bytes"
	"context"
	golog "log"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestJwtEdns(t *testing.T) {
	// Create a new JwtEdns Plugin. Use the test.ErrorHandler as the next plugin.
	j := JwtEdns{Next: test.ErrorHandler()}

	// Setup a new output buffer that is *not* standard output, so we can check if
	// jwt_edns is really being printed.
	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)
	// Create a new Recorder that captures the result, this isn't actually used in this test
	// as it just serves as something that implements the dns.ResponseWriter interface.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly, and check the result.
	j.ServeDNS(ctx, rec, r)
	if a := b.String(); !strings.Contains(a, "[INFO] plugin/jwt_edns: received request for domain: example.org") {
		t.Errorf("Failed to print '%s', got %s", "[INFO] plugin/jwt_edns: received request for domain: example.org", a)
	}
}

func TestJwtEdnsWithEDNSOption(t *testing.T) {
	// Create a new JwtEdns Plugin. Use the test.ErrorHandler as the next plugin.
	j := JwtEdns{Next: test.ErrorHandler()}

	// Setup a new output buffer to capture logs
	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)

	// Add EDNS0 with custom option 65001 (JWT token)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT

	// Add JWT token as EDNS0_LOCAL option with code 65001
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
	localOpt := &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(jwtToken)}
	opt.Option = []dns.EDNS0{localOpt}

	r.Extra = []dns.RR{opt}

	// Create a new Recorder
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly
	j.ServeDNS(ctx, rec, r)

	// Check that JWT token was found
	logOutput := b.String()
	if !strings.Contains(logOutput, "Found JWT token in EDNS option 65001") {
		t.Errorf("Expected to find JWT token log message, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, jwtToken) {
		t.Errorf("Expected to find JWT token '%s' in logs, got: %s", jwtToken, logOutput)
	}
}

func TestJwtEdnsWithoutEDNSOption(t *testing.T) {
	// Create a new JwtEdns Plugin. Use the test.ErrorHandler as the next plugin.
	j := JwtEdns{Next: test.ErrorHandler()}

	// Setup a new output buffer to capture logs
	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)

	// Add EDNS0 but without option 65001
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	r.Extra = []dns.RR{opt}

	// Create a new Recorder
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly
	j.ServeDNS(ctx, rec, r)

	// Check that no JWT token was found
	logOutput := b.String()
	if !strings.Contains(logOutput, "No JWT token found in EDNS options") {
		t.Errorf("Expected 'No JWT token found' log message, got: %s", logOutput)
	}
}
