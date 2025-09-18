// Package jwt_edns is a CoreDNS plugin that enforces JWT authorization via OPT records

package jwt_edns

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("jwt_edns")

// JwtEdns is a plugin that enforces JWT authorization via OPT records.
type JwtEdns struct {
	Next plugin.Handler
}

// ServeDNS implements the plugin.Handler interface. This method gets called when jwt_edns is used
// in a Server.
func (j JwtEdns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Step 1: Parse incoming DNS request for EDNS0 support
	opt := r.IsEdns0()
	if opt == nil {
		// No EDNS0 support, allow request to continue without JWT validation
		// Wrap for logging purposes
		pw := NewResponsePrinter(r, w)
		return plugin.NextOrFailure(j.Name(), j.Next, ctx, pw, r)
	}

	// Step 2: Extract OPT RR options and check for option code 65001
	const JWTOptionCode = 65001
	var jwtToken []byte

	for _, option := range opt.Option {
		if option.Option() == JWTOptionCode {
			// Cast to EDNS0_LOCAL to access Data field
			if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
				jwtToken = localOpt.Data
				log.Infof("Found JWT token in EDNS option 65001: %s", string(jwtToken))
				break
			}
		}
	}

	if jwtToken == nil {
		// No JWT token found, allow request to continue
		log.Info("No JWT token found in EDNS options")
		// Wrap for logging purposes
		pw := NewResponsePrinter(r, w)
		return plugin.NextOrFailure(j.Name(), j.Next, ctx, pw, r)
	}

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Wrap for logging purposes
	pw := NewResponsePrinter(r, w)

	// Call next plugin (if any).
	return plugin.NextOrFailure(j.Name(), j.Next, ctx, pw, r)
}

// Name implements the plugin.Handler interface.
func (j JwtEdns) Name() string { return "jwt edns plugin" }

// ResponsePrinter wrap a dns.ResponseWriter and will log domain requests when WriteMsg is called.
type ResponsePrinter struct {
	*dns.Msg
	dns.ResponseWriter
}

// NewResponsePrinter returns a ResponsePrinter.
func NewResponsePrinter(r *dns.Msg, w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{Msg: r, ResponseWriter: w}
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and logs the domain request.
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	domain := strings.TrimSuffix(r.Question[0].Name, ".")
	log.Info("received request for domain: " + domain)
	return r.ResponseWriter.WriteMsg(res)
}
