package artifact

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testIndexManifest() *v1.IndexManifest {
	amd64Digest := v1.Hash{Algorithm: "sha256", Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	arm64Digest := v1.Hash{Algorithm: "sha256", Hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	attestDigest := v1.Hash{Algorithm: "sha256", Hex: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}

	return &v1.IndexManifest{
		Manifests: []v1.Descriptor{
			{Digest: amd64Digest, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
			{Digest: arm64Digest, Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
			{Digest: attestDigest, Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"}},
		},
	}
}

var _ = Describe("index platform resolution", func() {
	Describe("platformDigestsFromIndexManifest", func() {
		It("extracts platform entries and skips unknown platforms", func() {
			entries := platformDigestsFromIndexManifest(testIndexManifest())

			Expect(entries).To(HaveLen(2))
			Expect(entries[0].Platform).To(Equal("linux/amd64"))
			Expect(entries[0].Digest).To(HavePrefix("sha256:aaaa"))
			Expect(entries[1].Platform).To(Equal("linux/arm64/v8"))
			Expect(entries[1].Digest).To(HavePrefix("sha256:bbbb"))
		})
	})

	DescribeTable("matchPlatformDigest",
		func(platform, expectedDigestPrefix, expectedErrSubstring string) {
			entries := platformDigestsFromIndexManifest(testIndexManifest())
			digest, err := matchPlatformDigest(entries, platform)

			if expectedErrSubstring != "" {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrSubstring))
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(digest).To(HavePrefix(expectedDigestPrefix))
		},

		Entry("exact match", "linux/amd64", "sha256:aaaa", ""),
		Entry("exact match with variant", "linux/arm64/v8", "sha256:bbbb", ""),
		Entry("os/arch match resolves single variant entry", "linux/arm64", "sha256:bbbb", ""),
		Entry("empty platform requires selection", "", "", "platform required"),
		Entry("empty platform lists available entries", "", "", "linux/amd64 → sha256:aaaa"),
		Entry("bare os does not prefix-match", "linux", "", `platform "linux" not found`),
		Entry("mismatch lists available entries", "linux/s390x", "", "linux/arm64/v8 → sha256:bbbb"),
		Entry("mismatch names the requested platform", "linux/s390x", "", `platform "linux/s390x" not found`),
	)

	DescribeTable("NormalizePlatform",
		func(input, expected, expectedErrSubstring string) {
			normalized, err := NormalizePlatform(input)

			if expectedErrSubstring != "" {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrSubstring))
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(normalized).To(Equal(expected))
		},

		Entry("empty stays empty", "", "", ""),
		Entry("plain os/arch passes through", "linux/amd64", "linux/amd64", ""),
		Entry("default arm64 variant is dropped", "linux/arm64/v8", "linux/arm64", ""),
		Entry("garbage is rejected", "not a platform!", "", "parse platform"),
	)

	DescribeTable("checkManifestPlatform",
		func(manifestPlatform, requested, expectedErrSubstring string) {
			err := checkManifestPlatform(manifestPlatform, "sha256:dddd", requested)

			if expectedErrSubstring != "" {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrSubstring))
				return
			}
			Expect(err).NotTo(HaveOccurred())
		},

		Entry("matching platform passes", "linux/amd64", "linux/amd64", ""),
		Entry("variant manifest matches os/arch request", "linux/arm/v7", "linux/arm", ""),
		Entry("mismatch is an error", "linux/amd64", "linux/arm64", "does not match"),
		Entry("mismatch names the manifest platform", "linux/amd64", "linux/arm64", "single-platform linux/amd64 image"),
	)

	Describe("matchPlatformDigest ambiguity", func() {
		It("rejects an os/arch that matches multiple variants", func() {
			entries := []PlatformDigest{
				{Platform: "linux/arm/v6", Digest: "sha256:d1"},
				{Platform: "linux/arm/v7", Digest: "sha256:d2"},
			}
			_, err := matchPlatformDigest(entries, "linux/arm")

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ambiguous"))
		})
	})

	Describe("ErrIndexPlatformRequired", func() {
		It("is detectable via errors.Is", func() {
			entries := platformDigestsFromIndexManifest(testIndexManifest())
			_, err := matchPlatformDigest(entries, "")

			Expect(err).To(MatchError(ErrIndexPlatformRequired))
		})
	})
})
