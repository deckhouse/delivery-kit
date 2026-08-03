package artifact_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/slug"
)

var _ = Describe("DigestHex", func() {
	DescribeTable("should parse various digest formats",
		func(input, expected string) {
			result, err := artifact.DigestHex(input)
			Expect(err).To(Succeed())
			Expect(result).To(Equal(expected))
		},
		Entry("sha256 digest", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Entry("sha512 digest", "sha512:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
	)

	DescribeTable("should error on malformed digests",
		func(input string) {
			_, err := artifact.DigestHex(input)
			Expect(err).To(HaveOccurred())
		},
		Entry("empty string", ""),
		Entry("missing algorithm prefix", "abc123"),
		Entry("invalid hex length", "sha256:abc123"),
		Entry("invalid characters", "sha256:xyz!"),
	)
})

var _ = Describe("FallbackTag", func() {
	const digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	DescribeTable("should compute correct fallback tag without image name",
		func(digest, expected string) {
			Expect(artifact.FallbackTag(digest, "")).To(Equal(expected))
		},
		Entry("sha256 digest", digest, "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
	)

	DescribeTable("should handle malformed digests gracefully (best-effort)",
		func(digest, expected string) {
			Expect(artifact.FallbackTag(digest, "")).To(Equal(expected))
		},
		Entry("plain hex without prefix", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Entry("digest with colons", "sha256:abc:def", "sha256-abc-def"),
		Entry("digest with slashes", "sha256:abc/def", "sha256-abc_def"),
		Entry("digest with at sign", "sha256:abc@def", "sha256-abc-def"),
	)

	It("should append the image name to the digest prefix", func() {
		Expect(artifact.FallbackTag(digest, "frontend")).To(Equal(artifact.FallbackTagDigestPrefix(digest) + "frontend"))
	})

	DescribeTable("should produce a valid docker tag for any image name",
		func(imageName string) {
			tag := artifact.FallbackTag(digest, imageName)
			Expect(slug.IsValidDockerTag(tag)).To(BeTrue(), "tag %q must be a valid docker tag", tag)
			Expect(tag).To(HavePrefix(artifact.FallbackTagDigestPrefix(digest)))
		},
		Entry("plain name", "frontend"),
		Entry("name with dashes", "my-backend-service"),
		Entry("name with slashes", "my-org/backend/api-gateway"),
		Entry("name with spaces", "my image"),
		Entry("name with uppercase", "MyImage"),
		Entry("very long name", strings.Repeat("very-long-image-name", 10)),
	)

	It("should produce different tags for different image names", func() {
		Expect(artifact.FallbackTag(digest, "frontend")).ToNot(Equal(artifact.FallbackTag(digest, "backend")))
	})

	It("should produce different tags for the same image name under different digests", func() {
		other := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		Expect(artifact.FallbackTag(digest, "frontend")).ToNot(Equal(artifact.FallbackTag(other, "frontend")))
	})
})

var _ = Describe("ParseFallbackTagDigest", func() {
	const (
		hex    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		digest = "sha256:" + hex
	)

	DescribeTable("should extract the parent digest",
		func(tag string) {
			parsed, ok := artifact.ParseFallbackTagDigest(tag)
			Expect(ok).To(BeTrue())
			Expect(parsed).To(Equal(digest))
		},
		Entry("digest-only tag written by previous versions", "sha256-"+hex),
		Entry("per-image tag", "sha256-"+hex+"-frontend"),
		Entry("per-image tag with slugged name", "sha256-"+hex+"-my-org-backend-abcdef12"),
	)

	DescribeTable("should reject foreign tags",
		func(tag string) {
			_, ok := artifact.ParseFallbackTagDigest(tag)
			Expect(ok).To(BeFalse())
		},
		Entry("managed image record", "managed-image-frontend"),
		Entry("metadata record", "meta-abc_def_ghi"),
		Entry("stage tag", hex+"-1784295824781"),
		Entry("truncated hex", "sha256-abc123"),
		Entry("non-hex payload", "sha256-"+strings.Repeat("z", 64)),
		Entry("hex not followed by separator", "sha256-"+hex+"x"),
	)
})
