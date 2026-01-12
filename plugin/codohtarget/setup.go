package codohtarget

import (
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("codohtarget", setup) }

func setup(c *caddy.Controller) error {
	t, err := parse(c)
	if err != nil {
		return plugin.Error("codohtarget", err)
	}

	c.OnStartup(t.OnStartup)
	c.OnFinalShutdown(t.OnFinalShutdown)

	// Don't call AddPlugin - this is an HTTP server, not a DNS handler
	return nil
}

func parse(c *caddy.Controller) (*odohTarget, error) {
	t := &odohTarget{
		addr:          ":8443",
		upstream:      "8.8.8.8:53",
		logQueries:    false,
		epochDuration: time.Hour,     // Default: 1 hour epochs
		rateLimit:     10,            // Default: 10 tokens per IP per epoch
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "port":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				t.addr = ":" + args[0]
			case "tls_cert":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				t.tlsCert = args[0]
			case "tls_key":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				t.tlsKey = args[0]
			case "upstream":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				t.upstream = args[0]
			case "cipher_suite":
				// Ignored for now - use odoh-go defaults
				c.RemainingArgs()
			case "log_queries":
				args := c.RemainingArgs()
				if len(args) == 1 && args[0] == "true" {
					t.logQueries = true
				}
			case "token_enabled":
				t.tokenEnabled = true
			case "epoch_duration":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				dur, err := time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid epoch_duration: %v", err)
				}
				t.epochDuration = dur
			case "rate_limit":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				limit, err := strconv.Atoi(args[0])
				if err != nil || limit <= 0 {
					return nil, c.Errf("invalid rate_limit: must be positive integer")
				}
				t.rateLimit = limit
			default:
				return nil, c.ArgErr()
			}
		}
	}

	// Validate required fields
	if t.tlsCert == "" || t.tlsKey == "" {
		return nil, c.Errf("tls_cert and tls_key are required")
	}

	return t, nil
}