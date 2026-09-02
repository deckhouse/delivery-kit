package build

import (
	"context"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/signing"
)

// anchorDigest is a thin wrapper that exercises the anchor branch of
// calculateDigest: pass HolisticInputs, get the platform-scoped hash.
func anchorDigest(targetPlatform string, deps []string) string {
	d, err := calculateDigest(context.Background(), "anchor", "", nil, nil, calculateDigestOptions{
		TargetPlatform: targetPlatform,
		Anchor:         true,
		HolisticInputs: deps,
	})
	if err != nil {
		panic(err)
	}
	return d
}

func anchorDigestWithELFSigning(opts signing.ELFSigningOptions, manifestSigningOptions signing.ManifestSigningOptions) string {
	d, err := calculateDigest(context.Background(), "anchor", "", nil, nil, calculateDigestOptions{
		TargetPlatform:         "linux/amd64",
		Anchor:                 true,
		HolisticInputs:         []string{"from-digest"},
		ELFSigningOptions:      opts,
		ManifestSigningOptions: manifestSigningOptions,
	})
	if err != nil {
		panic(err)
	}
	return d
}

func inHouseManifestSigningOptions(ctx SpecContext, certRef, chainRef string) signing.ManifestSigningOptions {
	signer, err := signing.NewSigner(ctx, signing.SignerOptions{
		KeyRef:           filepath.Join("..", "..", "test", "e2e", "build", "_fixtures", "signature", "inhouse", "keys", "delivery-kit_959497322.pem.key"),
		CertRef:          certRef,
		IntermediatesRef: chainRef,
	})
	Expect(err).To(Succeed())

	return signing.NewManifestSigningOptions(signer)
}

func withoutSigningWithHolistic(opts calculateDigestOptions) calculateDigestOptions {
	opts.Anchor = true
	opts.HolisticInputs = []string{"from-digest"}
	return opts
}

var _ = Describe("anchor holistic digest", func() {
	const targetPlatform = "linux/amd64"

	It("is deterministic for the same contributing stages", func() {
		deps := []string{"from-digest", "git-archive-digest", "run-digest"}
		Expect(anchorDigest(targetPlatform, deps)).
			To(Equal(anchorDigest(targetPlatform, deps)))
	})

	It("ignores empty stage contributions (gitCache/gitLatestPatch)", func() {
		withGitArchiveOnly := []string{"from-digest", "git-archive-digest"}
		withEmptyGitStages := []string{"from-digest", "git-archive-digest", "", ""}

		Expect(anchorDigest(targetPlatform, withGitArchiveOnly)).
			To(Equal(anchorDigest(targetPlatform, withEmptyGitStages)))
	})

	It("is unaffected by the position of empty contributions", func() {
		base := []string{"from-digest", "git-archive-digest", "run-digest"}
		withEmptyInterleaved := []string{"from-digest", "", "git-archive-digest", "", "run-digest", ""}

		Expect(anchorDigest(targetPlatform, base)).
			To(Equal(anchorDigest(targetPlatform, withEmptyInterleaved)))
	})

	It("is unaffected by absent optional empty stages (install/setup/dependencies)", func() {
		withoutOptional := []string{"from-digest", "git-archive-digest"}
		withOptionalEmpty := []string{"", "from-digest", "", "git-archive-digest", ""}

		Expect(anchorDigest(targetPlatform, withoutOptional)).
			To(Equal(anchorDigest(targetPlatform, withOptionalEmpty)))
	})

	It("changes when a contributing stage changes", func() {
		Expect(anchorDigest(targetPlatform, []string{"from-digest", "git-archive-v1"})).
			NotTo(Equal(anchorDigest(targetPlatform, []string{"from-digest", "git-archive-v2"})))
	})

	It("changes when the target platform changes", func() {
		deps := []string{"from-digest", "git-archive-digest"}
		Expect(anchorDigest("linux/amd64", deps)).
			NotTo(Equal(anchorDigest("linux/arm64", deps)))
	})

	Describe("ELF signing identities", func() {
		It("is deterministic for an unchanged BSign fingerprint", func() {
			opts := signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-a"}

			Expect(anchorDigestWithELFSigning(opts, signing.ManifestSigningOptions{})).To(Equal(anchorDigestWithELFSigning(opts, signing.ManifestSigningOptions{})))
		})

		It("changes when the BSign fingerprint changes", func() {
			first := signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-a"}
			second := signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-b"}

			Expect(anchorDigestWithELFSigning(first, signing.ManifestSigningOptions{})).NotTo(Equal(anchorDigestWithELFSigning(second, signing.ManifestSigningOptions{})))
		})

		It("excludes private BSign material when BSign is disabled", func() {
			first := signing.ELFSigningOptions{PGPPrivateKeyFingerprint: "fingerprint-a", PGPPrivateKeyPassphrase: "passphrase-a"}
			second := signing.ELFSigningOptions{PGPPrivateKeyFingerprint: "fingerprint-b", PGPPrivateKeyPassphrase: "passphrase-b"}

			Expect(anchorDigestWithELFSigning(first, signing.ManifestSigningOptions{})).To(Equal(anchorDigestWithELFSigning(second, signing.ManifestSigningOptions{})))
		})

		It("changes when the InHouse signing certificate changes", func(ctx SpecContext) {
			keysDir := filepath.Join("..", "..", "test", "e2e", "build", "_fixtures", "signature", "inhouse", "keys")
			withoutCertificate := signing.NewManifestSigningOptions(&signing.Signer{})
			withCertificate := inHouseManifestSigningOptions(
				ctx,
				filepath.Join(keysDir, "delivery-kit_1666162742.pem.crt"),
				"",
			)
			elfSigningOptions := signing.ELFSigningOptions{InHouseEnabled: true}

			Expect(anchorDigestWithELFSigning(elfSigningOptions, withoutCertificate)).NotTo(Equal(anchorDigestWithELFSigning(elfSigningOptions, withCertificate)))
		})

		It("changes when the InHouse signing chain changes", func(ctx SpecContext) {
			keysDir := filepath.Join("..", "..", "test", "e2e", "build", "_fixtures", "signature", "inhouse", "keys")
			certRef := filepath.Join(keysDir, "delivery-kit_1666162742.pem.crt")
			withoutChain := inHouseManifestSigningOptions(ctx, certRef, "")
			withChain := inHouseManifestSigningOptions(ctx, certRef, filepath.Join(keysDir, "delivery-kit_chain_3247019714.pem.crt"))
			elfSigningOptions := signing.ELFSigningOptions{InHouseEnabled: true}

			Expect(anchorDigestWithELFSigning(elfSigningOptions, withoutChain)).NotTo(Equal(anchorDigestWithELFSigning(elfSigningOptions, withChain)))
		})

		It("uses the same BSign identity response in anchor and non-anchor paths", func(ctx SpecContext) {
			withoutSigning := calculateDigestOptions{TargetPlatform: "linux/amd64"}
			withSigning := calculateDigestOptions{
				TargetPlatform:    "linux/amd64",
				ELFSigningOptions: signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-a"},
			}

			anchorWithout, err := calculateDigest(ctx, "anchor", "", nil, nil, withoutSigningWithHolistic(withoutSigning))
			Expect(err).To(Succeed())
			anchorWith, err := calculateDigest(ctx, "anchor", "", nil, nil, withoutSigningWithHolistic(withSigning))
			Expect(err).To(Succeed())
			nonAnchorWithout, err := calculateDigest(ctx, "stage", "", nil, nil, withoutSigning)
			Expect(err).To(Succeed())
			nonAnchorWith, err := calculateDigest(ctx, "stage", "", nil, nil, withSigning)
			Expect(err).To(Succeed())

			Expect(anchorWith).NotTo(Equal(anchorWithout))
			Expect(nonAnchorWith).NotTo(Equal(nonAnchorWithout))
		})
	})

	It("anchor path is engaged even when every input is empty", func() {
		nonAnchor, err := calculateDigest(context.Background(), "anchor", "", nil, nil, calculateDigestOptions{TargetPlatform: targetPlatform})
		Expect(err).NotTo(HaveOccurred())

		Expect(anchorDigest(targetPlatform, nil)).NotTo(Equal(nonAnchor),
			"anchor digest with no inputs must not silently fall back to the chain-based digest formula")
		Expect(anchorDigest(targetPlatform, nil)).
			To(Equal(anchorDigest(targetPlatform, []string{"", ""})),
				"anchor digest ignores empty inputs regardless of count")
	})
})
