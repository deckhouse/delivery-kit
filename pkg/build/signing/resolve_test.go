package signing_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/signing"
)

var _ = Describe("ResolveSigningGate", func() {
	DescribeTable("signing gate scenarios",
		func(opts signing.ResolveSigningGateOptions, expectErr string, expectSbom, expectManifest, expectSignerNonZero bool) {
			result, err := signing.ResolveSigningGate(opts)

			if expectErr != "" {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectErr))
				return
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(result.SbomSigningOptions.Enabled).To(Equal(expectSbom))
			Expect(result.ManifestSigningOptions.Enabled).To(Equal(expectManifest))
			Expect(!result.SignerOptions.IsZero()).To(Equal(expectSignerNonZero))
		},
		Entry("nothing set → both disabled",
			signing.ResolveSigningGateOptions{},
			"", false, false, false,
		),
		Entry("key+cert without --sign-manifest → sbom enabled, manifest disabled",
			signing.ResolveSigningGateOptions{SignKey: "key.pem", SignCert: "cert.pem"},
			"", true, false, true,
		),
		Entry("key without cert → error",
			signing.ResolveSigningGateOptions{SignKey: "key.pem"},
			"signing certificate is required", false, false, false,
		),
		Entry("key+cert+--sign-manifest → both enabled",
			signing.ResolveSigningGateOptions{SignKey: "key.pem", SignCert: "cert.pem", SignManifest: true},
			"", true, true, true,
		),
		Entry("--sign-manifest without key → error",
			signing.ResolveSigningGateOptions{SignManifest: true},
			"signing key is required", false, false, false,
		),
		Entry("--sign-manifest with key but no cert → error",
			signing.ResolveSigningGateOptions{SignKey: "key.pem", SignManifest: true},
			"signing certificate is required", false, false, false,
		),
		Entry("key+cert with intermediates → signer options include intermediates",
			signing.ResolveSigningGateOptions{SignKey: "key.pem", SignCert: "cert.pem", SignIntermediates: "chain.pem"},
			"", true, false, true,
		),
		Entry("--sign-elf-files with key+cert → signer options non-zero, sbom enabled, manifest disabled",
			signing.ResolveSigningGateOptions{SignKey: "key.pem", SignCert: "cert.pem", SignELFFiles: true},
			"", true, false, true,
		),
		Entry("--sign-elf-files without key → error",
			signing.ResolveSigningGateOptions{SignELFFiles: true},
			"signing key is required", false, false, false,
		),
		Entry("--sign-elf-files with key but no cert → error",
			signing.ResolveSigningGateOptions{SignKey: "key.pem", SignELFFiles: true},
			"signing certificate is required", false, false, false,
		),
	)

	It("key+cert+--sign-manifest produces signer options with same key/cert refs", func() {
		result, err := signing.ResolveSigningGate(signing.ResolveSigningGateOptions{
			SignKey:  "key.pem",
			SignCert: "cert.pem",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.SignerOptions.KeyRef).To(Equal("key.pem"))
		Expect(result.SignerOptions.CertRef).To(Equal("cert.pem"))
	})
})
