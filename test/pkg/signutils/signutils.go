package signutils

import (
	"crypto"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"
)

// GenerateSignerVerifier produces an in-memory sigstore signer/verifier backed
// by key material from the delivery-kit-sdk test helpers, so unit tests share
// one key-generation path with the e2e suites.
func GenerateSignerVerifier(keyType cert_utils.KeyType) signature.SignerVerifier {
	certs := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
		KeyType:           keyType,
		UseBase64Encoding: true,
	})

	sv, err := signature.LoadSignerVerifier(certs.PrivKey, crypto.SHA256)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	return sv
}
