//go:build !sgxverify

package codohtarget

// verifyQuoteAndPubKey verifies the SGX quote and checks that the public key
// is properly bound to the attested enclave.
// This version is used when building without SGX verification support.
// It logs warnings and proceeds without verification.
//
// For production use with actual SGX attestation verification, build with:
//
//	go build -tags sgxverify ./...
//
// This requires the Open Enclave SDK to be installed.
func verifyQuoteAndPubKey(quote, pubKeyBytes, expectedMRSigner []byte) error {
	if len(quote) == 0 {
		log.Warning("Empty quote received - enclave running in simulation mode")
		log.Warning("Proceeding without attestation verification (INSECURE)")
	} else {
		log.Warning("SGX quote verification not available (build without sgxverify tag)")
		log.Warning("Proceeding without attestation verification (INSECURE)")
		log.Warning("For production, rebuild with -tags sgxverify and Open Enclave SDK")
	}
	return nil
}
