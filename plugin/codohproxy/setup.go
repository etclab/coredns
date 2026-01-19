package codohproxy

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("codohproxy", setup) }

func setup(c *caddy.Controller) error {
	p, err := parse(c)
	if err != nil {
		return plugin.Error("codohproxy", err)
	}

	c.OnStartup(p.OnStartup)
	c.OnFinalShutdown(p.OnFinalShutdown)

	// Don't call AddPlugin - this is an HTTP server, not a DNS handler
	return nil
}

func parse(c *caddy.Controller) (*odohProxy, error) {
	p := &odohProxy{
		addr:                 ":8080",
		insecureSkipVerify:   false,
		enclaveSocketPath:    "/tmp/codoh-enclave.sock",
		enclaveBypassOnFail:  true,
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "target":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				p.targetURL = args[0]
			case "port":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				p.addr = ":" + args[0]
			case "tls_cert":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				p.tlsCert = args[0]
			case "tls_key":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				p.tlsKey = args[0]
			case "insecure_skip_verify":
				args := c.RemainingArgs()
				if len(args) == 1 && args[0] == "true" {
					p.insecureSkipVerify = true
				}
			case "verify_url":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				p.verifyURL = args[0]
			// Phase 2: Enclave configuration
			case "enclave_enabled":
				p.enclaveEnabled = true
			case "enclave_socket":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				p.enclaveSocketPath = args[0]
			case "enclave_bypass_on_failure":
				args := c.RemainingArgs()
				if len(args) == 1 && args[0] == "false" {
					p.enclaveBypassOnFail = false
				}
			default:
				return nil, c.ArgErr()
			}
		}
	}

	// Validate required fields
	if p.targetURL == "" {
		return nil, c.Errf("target is required")
	}
	if p.tlsCert == "" || p.tlsKey == "" {
		return nil, c.Errf("tls_cert and tls_key are required")
	}

	return p, nil
}