// Package jwt_edns is a CoreDNS plugin that enforces JWT authorization via OPT records

package jwt_edns

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/golang-jwt/jwt/v5"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("jwt_edns")

// loadPublicKeyFromFile loads the public key from a file with a specific algorithm
func loadPublicKeyFromFile(keyPath string, algorithm string) (interface{}, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	return loadPublicKeyFromPEM(keyData, algorithm)
}

// loadPublicKeyFromPEM loads a public key from PEM data with the specified algorithm
func loadPublicKeyFromPEM(keyData []byte, algorithm string) (interface{}, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch algorithm {
	case "rsa":
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if rsaPub, ok := pub.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
			return nil, fmt.Errorf("key is not an RSA public key")
		}
		return nil, fmt.Errorf("failed to parse RSA public key")
	case "ecdsa":
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
				return ecdsaPub, nil
			}
			return nil, fmt.Errorf("key is not an ECDSA public key")
		}
		return nil, fmt.Errorf("failed to parse ECDSA public key")
	case "eddsa":
		// Handle raw Ed25519 public key (32 bytes)
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
		// Fallback to PKIX parsing for DER-encoded keys
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ed25519Pub, ok := pub.(ed25519.PublicKey); ok {
				return ed25519Pub, nil
			}
			return nil, fmt.Errorf("key is not an Ed25519 public key")
		}
		return nil, fmt.Errorf("failed to parse Ed25519 public key")
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// validateJWTWithClaims validates a JWT token and returns validated claims
func (j *JwtEdns) validateJWTWithClaims(tokenString string, requestedZone string) (*JWTClaims, error) {
	if j.publicKey == nil {
		return nil, fmt.Errorf("no public key available for JWT validation")
	}

	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			if _, ok := j.publicKey.(*rsa.PublicKey); !ok {
				return nil, fmt.Errorf("invalid key type for RSA")
			}
		case *jwt.SigningMethodECDSA:
			if _, ok := j.publicKey.(*ecdsa.PublicKey); !ok {
				return nil, fmt.Errorf("invalid key type for ECDSA")
			}
		case *jwt.SigningMethodEd25519:
			if _, ok := j.publicKey.(ed25519.PublicKey); !ok {
				return nil, fmt.Errorf("invalid key type for EdDSA")
			}
		default:
			return nil, fmt.Errorf("unsupported signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Validate custom claims
	if claims.ClientID == "" {
		return nil, fmt.Errorf("missing required client_id claim")
	}

	// Check if "query" permission is present
	hasQueryPermission := false
	for _, perm := range claims.Permissions {
		if perm == "query" {
			hasQueryPermission = true
			break
		}
	}
	if !hasQueryPermission {
		return nil, fmt.Errorf("missing required 'query' permission")
	}

	// Validate zone access if allowed_zones is specified
	if len(claims.AllowedZones) > 0 && requestedZone != "" {
		zoneAllowed := false
		// Remove trailing dot for comparison
		normalizedZone := strings.TrimSuffix(requestedZone, ".")

		for _, allowedZone := range claims.AllowedZones {
			allowedZoneNorm := strings.TrimSuffix(allowedZone, ".")
			if normalizedZone == allowedZoneNorm || strings.HasSuffix(normalizedZone, "."+allowedZoneNorm) {
				zoneAllowed = true
				break
			}
		}
		if !zoneAllowed {
			return nil, fmt.Errorf("zone '%s' not in allowed zones: %v", normalizedZone, claims.AllowedZones)
		}
	}

	return claims, nil
}

// JwtEdns is a plugin that enforces JWT authorization via OPT records.
type JwtEdns struct {
	Next      plugin.Handler
	publicKey interface{}
}

// JWTClaims represents the custom JWT claims for CoreDNS authorization
type JWTClaims struct {
	ClientID     string   `json:"client_id"`
	Permissions  []string `json:"permissions"`
	AllowedZones []string `json:"allowed_zones,omitempty"`
	jwt.RegisteredClaims
}

const (
	JWTOptionCode = 65001
)

// ServeDNS implements the plugin.Handler interface. This method gets called when jwt_edns is used
// in a Server.
func (j *JwtEdns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Debug("JWT EDNS plugin processing DNS request")

	// Step 0: Check if public key is available - refuse all requests if not
	if j.publicKey == nil {
		log.Error("JWT validation required but no public key configured")
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return dns.RcodeRefused, nil
	}

	// Step 1: Parse incoming DNS request for EDNS0 support
	opt := r.IsEdns0()
	if opt == nil {
		// No EDNS0 support - refuse request as JWT is required
		log.Info("No EDNS0 support - JWT token required")
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return dns.RcodeRefused, nil
	}

	// Step 2: Extract OPT RR options and check for option code JWTOptionCode
	var jwtToken []byte

	for _, option := range opt.Option {
		if option.Option() == JWTOptionCode {
			// Cast to EDNS0_LOCAL to access Data field
			if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
				jwtToken = localOpt.Data
				log.Infof("Found JWT token in EDNS option 65001")
				break
			}
		}
	}

	if jwtToken == nil {
		// No JWT token found - refuse request as JWT is required
		log.Info("No JWT token found in EDNS options - JWT token required")
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return dns.RcodeRefused, nil
	}

	// Step 3: Validate JWT token and claims
	tokenString := string(jwtToken)

	// Get the requested zone from the first question
	var requestedZone string
	if len(r.Question) > 0 {
		requestedZone = r.Question[0].Name
	}

	// Validate the JWT token and claims
	claims, err := j.validateJWTWithClaims(tokenString, requestedZone)
	if err != nil {
		log.Errorf("JWT validation failed: %v", err)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return dns.RcodeRefused, nil
	}

	log.Infof("JWT token validated successfully for client: %s", claims.ClientID)

	// Export metric with the server label set to the current server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Log the domain request.
	if len(r.Question) > 0 {
		domain := strings.TrimSuffix(r.Question[0].Name, ".")
		log.Info("received request for domain: " + domain)
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(j.Name(), j.Next, ctx, w, r)
}

// Name implements the plugin.Handler interface.
func (j JwtEdns) Name() string { return "jwt_edns" }
