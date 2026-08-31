package build

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/signing"
)

// anchorDigest is a thin wrapper that exercises the anchor branch of
// calculateDigest: pass HolisticInputs, get the platform-scoped hash.
func anchorDigest(targetPlatform string, deps []string) string {
	return anchorDigestWithOptions(calculateDigestOptions{
		TargetPlatform: targetPlatform,
		Anchor:         true,
		HolisticInputs: deps,
	})
}

func anchorDigestWithOptions(opts calculateDigestOptions) string {
	d, err := calculateDigest(context.Background(), "anchor", "", nil, nil, opts)
	if err != nil {
		panic(err)
	}
	return d
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

	It("changes when the explicitly supplied build cache version changes", func() {
		base := calculateDigestOptions{
			TargetPlatform:    targetPlatform,
			BuildCacheVersion: "cache-v1",
			Anchor:            true,
			HolisticInputs:    []string{"from-digest"},
		}

		Expect(anchorDigestWithOptions(base)).To(Equal(anchorDigestWithOptions(base)))
		base.BuildCacheVersion = "cache-v2"
		Expect(anchorDigestWithOptions(base)).NotTo(Equal(anchorDigestWithOptions(calculateDigestOptions{
			TargetPlatform:    targetPlatform,
			BuildCacheVersion: "cache-v1",
			Anchor:            true,
			HolisticInputs:    []string{"from-digest"},
		})))
	})

	DescribeTable("distinguishes ELF signing states",
		func(base, changed signing.ELFSigningOptions) {
			common := calculateDigestOptions{
				TargetPlatform:    targetPlatform,
				BuildCacheVersion: "cache-v1",
				Anchor:            true,
				HolisticInputs:    []string{"from-digest"},
				ELFSigningOptions: base,
			}
			changedOpts := common
			changedOpts.ELFSigningOptions = changed

			Expect(anchorDigestWithOptions(common)).NotTo(Equal(anchorDigestWithOptions(changedOpts)))
		},
		Entry("disabled to BSign", signing.ELFSigningOptions{}, signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-1"}),
		Entry("BSign key rotation", signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-1"}, signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-2"}),
	)

	It("does not include the ELF signing passphrase in the anchor digest", func() {
		base := calculateDigestOptions{
			TargetPlatform:    targetPlatform,
			BuildCacheVersion: "cache-v1",
			Anchor:            true,
			HolisticInputs:    []string{"from-digest"},
			ELFSigningOptions: signing.ELFSigningOptions{BsignEnabled: true, PGPPrivateKeyFingerprint: "fingerprint-1"},
		}
		changed := base
		changed.ELFSigningOptions.PGPPrivateKeyPassphrase = "different-secret"

		Expect(anchorDigestWithOptions(changed)).To(Equal(anchorDigestWithOptions(base)))
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
