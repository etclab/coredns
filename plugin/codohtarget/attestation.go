package codohtarget

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AttestResponse is returned by the enclave's /attest endpoint.
type AttestResponse struct {
	Quote  string `json:"quote"`  // Base64-encoded SGX quote
	PubKey string `json:"pubkey"` // Base64-encoded HPKE public key
}

// ProvisionRequest is sent to the enclave's /provision endpoint.
type ProvisionRequest struct {
	SigningPublicKey string `json:"signing_pubkey"` // Base64-encoded Ed25519 public key
}

// ProvisionSigningKey fetches the SGX quote from the enclave, verifies it,
// and provisions the target's Ed25519 signing public key.
func ProvisionSigningKey(enclaveURL string, expectedMRSigner []byte, signingKey *SigningKey) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	// Fetch attestation with retry
	attestResp, err := fetchAttestationWithRetry(client, enclaveURL+"/attest", 5)
	if err != nil {
		return fmt.Errorf("fetch attestation: %w", err)
	}

	// Decode quote
	quote, err := base64.StdEncoding.DecodeString(attestResp.Quote)
	if err != nil {
		return fmt.Errorf("decode quote: %w", err)
	}

	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(attestResp.PubKey)
	if err != nil {
		return fmt.Errorf("decode pubkey: %w", err)
	}

	// Verify the SGX quote and extract/validate the public key
	if err := verifyQuoteAndPubKey(quote, pubKeyBytes, expectedMRSigner); err != nil {
		return err
	}

	// Provision signing pubkey
	signingPubKey := signingKey.PublicKeyBytes()
	if err := provisionSigningKeyWithRetry(client, enclaveURL+"/provision", signingPubKey, 5); err != nil {
		return fmt.Errorf("provision signing key: %w", err)
	}

	return nil
}

// fetchAttestationWithRetry fetches the attestation response with exponential backoff.
func fetchAttestationWithRetry(client *http.Client, url string, maxAttempts int) (*AttestResponse, error) {
	var lastErr error
	backoff := time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			log.Warningf("Attestation fetch attempt %d/%d failed: %v", attempt, maxAttempts, err)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				if backoff > 16*time.Second {
					backoff = 16 * time.Second
				}
			}
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("attestation request failed: %d %s", resp.StatusCode, string(body))
			log.Warningf("Attestation fetch attempt %d/%d failed: %v", attempt, maxAttempts, lastErr)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				if backoff > 16*time.Second {
					backoff = 16 * time.Second
				}
			}
			continue
		}

		var attestResp AttestResponse
		if err := json.NewDecoder(resp.Body).Decode(&attestResp); err != nil {
			return nil, fmt.Errorf("decode attestation response: %w", err)
		}

		return &attestResp, nil
	}

	return nil, fmt.Errorf("attestation fetch failed after %d attempts: %w", maxAttempts, lastErr)
}

// provisionSigningKeyWithRetry sends the signing pubkey to the enclave with exponential backoff.
func provisionSigningKeyWithRetry(client *http.Client, url string, signingPubKey []byte, maxAttempts int) error {
	var lastErr error
	backoff := time.Second

	req := ProvisionRequest{
		SigningPublicKey: base64.StdEncoding.EncodeToString(signingPubKey),
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal provision request: %w", err)
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			lastErr = err
			log.Warningf("Provision attempt %d/%d failed: %v", attempt, maxAttempts, err)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				if backoff > 16*time.Second {
					backoff = 16 * time.Second
				}
			}
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("provision request failed: %d %s", resp.StatusCode, string(body))
			log.Warningf("Provision attempt %d/%d failed: %v", attempt, maxAttempts, lastErr)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				if backoff > 16*time.Second {
					backoff = 16 * time.Second
				}
			}
			continue
		}

		return nil
	}

	return fmt.Errorf("provision failed after %d attempts: %w", maxAttempts, lastErr)
}
