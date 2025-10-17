package jwt_edns

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("jwt_edns", setup) }

// setup is the function that gets called when the config parser sees the token "jwt_edns". Setup is responsible
// for parsing any extra options the jwt_edns plugin may have. The first token this function sees is "jwt_edns".
func setup(c *caddy.Controller) error {
	c.Next() // Ignore "jwt_edns" and give us the next token.

	var algorithm string = "eddsa" // default algorithm
	var keyFile string

	// Parse configuration arguments
	for c.NextBlock() {
		switch c.Val() {
		case "algorithm":
			if !c.NextArg() {
				return plugin.Error("jwt_edns", c.ArgErr())
			}
			algorithm = c.Val()
			if algorithm != "rsa" && algorithm != "ecdsa" && algorithm != "eddsa" {
				return plugin.Error("jwt_edns", c.Errf("unsupported algorithm: %s", algorithm))
			}
		case "key_file":
			if !c.NextArg() {
				return plugin.Error("jwt_edns", c.ArgErr())
			}
			keyFile = c.Val()
		default:
			return plugin.Error("jwt_edns", c.Errf("unknown property '%s'", c.Val()))
		}
	}

	// key_file is required
	if keyFile == "" {
		return plugin.Error("jwt_edns", c.Errf("key_file directive is required"))
	}

	// Load public key during setup with specified algorithm
	publicKey, err := loadPublicKeyFromFile(keyFile, algorithm)
	if err != nil {
		return plugin.Error("jwt_edns", err)
	}

	log.Infof("JWT EDNS plugin loaded with %s algorithm public key from %s", algorithm, keyFile)

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &JwtEdns{Next: next, publicKey: publicKey}
	})

	// All OK, return a nil error.
	return nil
}
