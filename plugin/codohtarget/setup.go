package codohtarget

import (
	"encoding/hex"

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

	return nil
}

func parse(c *caddy.Controller) (*odohTarget, error) {
	t := &odohTarget{
		addr:       ":8443",
		upstream:   "8.8.8.8:53",
		logQueries: false,
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
			case "log_queries":
				args := c.RemainingArgs()
				if len(args) == 1 && args[0] == "true" {
					t.logQueries = true
				}
			case "enclave_url":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				t.enclaveURL = args[0]
			case "enclave_mrsigner":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				mrsigner, err := hex.DecodeString(args[0])
				if err != nil {
					return nil, c.Errf("invalid enclave_mrsigner: %v", err)
				}
				if len(mrsigner) != 32 {
					return nil, c.Errf("enclave_mrsigner must be 32 bytes (64 hex chars)")
				}
				t.expectedMRSigner = mrsigner
			case "signing_key":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				t.signingKeyPath = args[0]
			default:
				return nil, c.ArgErr()
			}
		}
	}

	if t.tlsCert == "" || t.tlsKey == "" {
		return nil, c.Errf("tls_cert and tls_key are required")
	}

	return t, nil
}
