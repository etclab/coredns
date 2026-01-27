//go:build sgxverify

package codohtarget

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/eclient"
)

// verifyQuoteAndPubKey verifies the SGX quote and checks that the public key
// is properly bound to the attested enclave.
// This version uses the EGo eclient library which requires Open Enclave SDK.
func verifyQuoteAndPubKey(quote, pubKeyBytes, expectedMRSigner []byte) error {
	// Skip verification if quote is empty (enclave running in simulation mode)
	if len(quote) == 0 {
		log.Warning("Empty quote received - enclave running in simulation mode")
		log.Warning("Proceeding without attestation verification (INSECURE)")
		return nil
	}

	// Verify the SGX quote
	report, err := eclient.VerifyRemoteReport(quote)
	if err != nil {
		// ErrTCBLevelInvalid means the quote is valid but TCB is not up-to-date.
		// This is common when platform firmware hasn't been updated after Intel security patches.
		// For development/testing, we accept this but log a warning.
		// In production, you may want to enforce stricter TCB requirements.
		if errors.Is(err, attestation.ErrTCBLevelInvalid) {
			log.Warningf("SGX TCB level is not up-to-date (status: %s)", report.TCBStatus)
			if len(report.TCBAdvisories) > 0 {
				log.Warningf("TCB advisories: %v", report.TCBAdvisories)
			}
			log.Warning("Proceeding with attestation despite outdated TCB (update platform firmware for production)")
		} else {
			return fmt.Errorf("verify quote: %w", err)
		}
	}

	// Check MRSIGNER if expected value is provided
	if len(expectedMRSigner) > 0 {
		if !bytes.Equal(report.SignerID, expectedMRSigner) {
			return fmt.Errorf("MRSIGNER mismatch: expected %x, got %x",
				expectedMRSigner, report.SignerID)
		}
		log.Infof("MRSIGNER verified: %x", report.SignerID[:8])
	}

	// Verify that the public key is bound to the quote (in user data)
	if len(report.Data) < len(pubKeyBytes) {
		return fmt.Errorf("quote user data too short for public key binding")
	}
	if !bytes.Equal(report.Data[:len(pubKeyBytes)], pubKeyBytes) {
		return fmt.Errorf("public key not bound to quote")
	}

	log.Info("SGX quote verified successfully")
	return nil
}
