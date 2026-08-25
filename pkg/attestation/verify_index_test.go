package attestation

import (
	"net/http/httptest"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/test/pkg/signutils"
)

var _ = Describe("VerifyIndex", func() {
	const imageName = "app"

	var (
		server      *httptest.Server
		repo        string
		remoteOpts  []remote.Option
		indexDigest string
		amd64Digest string
		arm64Digest string

		signerA   signature.SignerVerifier
		verifierA signature.Verifier
		signerB   signature.SignerVerifier

		cyclonedxType string
		predicate     []byte
	)

	BeforeEach(func(ctx SpecContext) {
		server = httptest.NewServer(registry.New())
		repo = strings.TrimPrefix(server.URL, "http://") + "/test/app"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}

		signerA = signutils.GenerateSignerVerifier(cert_utils.KeyType_ED25519)
		verifierA = signerA
		signerB = signutils.GenerateSignerVerifier(cert_utils.KeyType_ED25519)

		var err error
		cyclonedxType, err = ResolvePredicateType("cyclonedx")
		Expect(err).NotTo(HaveOccurred())

		predicate = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)

		amd64Digest = writeRandomImage(ctx, repo, remoteOpts)
		arm64Digest = writeRandomImage(ctx, repo, remoteOpts)
		indexDigest = writeIndex(ctx, repo, remoteOpts, []indexEntry{
			{digest: amd64Digest, platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
			{digest: arm64Digest, platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		})
	})

	AfterEach(func() {
		server.Close()
	})

	attachSignedBundle := func(ctx SpecContext, digest, predicateType string, signer signature.SignerVerifier) {
		stmtBytes, err := WrapInInTotoStatement(predicate, predicateType, repo, strings.TrimPrefix(digest, "sha256:"))
		Expect(err).NotTo(HaveOccurred())

		envelopeJSON, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, signer)
		Expect(err).NotTo(HaveOccurred())

		pub, err := signer.PublicKey()
		Expect(err).NotTo(HaveOccurred())

		bundleJSON, err := WrapInBundle(envelopeJSON, pub)
		Expect(err).NotTo(HaveOccurred())

		store := artifact.NewOCIStore(repo, imageName, remoteOpts...)
		Expect(store.Attach(ctx, digest, BundleMediaType, bundleJSON, "", "", predicateType)).To(Succeed())
	}

	attachUnsignedBareDSSE := func(ctx SpecContext, digest string) {
		stmtBytes, err := WrapInInTotoStatement(predicate, cyclonedxType, repo, strings.TrimPrefix(digest, "sha256:"))
		Expect(err).NotTo(HaveOccurred())

		envelopeJSON, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, nil)
		Expect(err).NotTo(HaveOccurred())

		store := artifact.NewOCIStore(repo, imageName, remoteOpts...)
		Expect(store.Attach(ctx, digest, DSSEMediaType, envelopeJSON, "", "", cyclonedxType)).To(Succeed())
	}

	resultByPlatform := func(results []PlatformVerifyResult) map[string]PlatformVerifyResult {
		byPlatform := map[string]PlatformVerifyResult{}
		for _, result := range results {
			byPlatform[result.Platform] = result
		}
		return byPlatform
	}

	It("verifies every platform and reports success when all attestations are signed and valid", func(ctx SpecContext) {
		attachSignedBundle(ctx, amd64Digest, cyclonedxType, signerA)
		attachSignedBundle(ctx, arm64Digest, cyclonedxType, signerA)

		results, err := VerifyIndex(ctx, repo, indexDigest, imageName, "cyclonedx", []signature.Verifier{verifierA}, remoteOpts...)
		Expect(err).NotTo(HaveOccurred())
		Expect(results).To(HaveLen(2))

		byPlatform := resultByPlatform(results)
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			Expect(byPlatform[platform].Status).To(Equal(PlatformVerifyStatusVerified), platform)
			Expect(byPlatform[platform].Err).NotTo(HaveOccurred(), platform)
		}
		Expect(byPlatform["linux/amd64"].Digest).To(Equal(amd64Digest))
		Expect(byPlatform["linux/arm64"].Digest).To(Equal(arm64Digest))

		Expect(VerifyIndexResultError(results)).To(Succeed())
	})

	It("excludes index entries without a real platform from verification", func(ctx SpecContext) {
		attestManifestDigest := writeRandomImage(ctx, repo, remoteOpts)
		indexWithUnknown := writeIndex(ctx, repo, remoteOpts, []indexEntry{
			{digest: amd64Digest, platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
			{digest: arm64Digest, platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
			{digest: attestManifestDigest, platform: &v1.Platform{OS: "unknown", Architecture: "unknown"}},
		})

		attachSignedBundle(ctx, amd64Digest, cyclonedxType, signerA)
		attachSignedBundle(ctx, arm64Digest, cyclonedxType, signerA)

		results, err := VerifyIndex(ctx, repo, indexWithUnknown, imageName, "cyclonedx", []signature.Verifier{verifierA}, remoteOpts...)
		Expect(err).NotTo(HaveOccurred())
		Expect(results).To(HaveLen(2), "unknown/unknown entry must not be verified")
		Expect(VerifyIndexResultError(results)).To(Succeed())
	})

	DescribeTable("classifies a failing platform while the healthy platform stays verified",
		func(ctx SpecContext, arm64Setup func(ctx SpecContext), expectedStatus PlatformVerifyStatus, expectedErrSubstring string) {
			attachSignedBundle(ctx, amd64Digest, cyclonedxType, signerA)
			arm64Setup(ctx)

			results, err := VerifyIndex(ctx, repo, indexDigest, imageName, "cyclonedx", []signature.Verifier{verifierA}, remoteOpts...)
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))

			byPlatform := resultByPlatform(results)
			Expect(byPlatform["linux/amd64"].Status).To(Equal(PlatformVerifyStatusVerified))
			Expect(byPlatform["linux/arm64"].Status).To(Equal(expectedStatus))
			Expect(byPlatform["linux/arm64"].Err).To(MatchError(ContainSubstring(expectedErrSubstring)))

			aggregateErr := VerifyIndexResultError(results)
			Expect(aggregateErr).To(HaveOccurred())
			Expect(aggregateErr.Error()).To(ContainSubstring("1 of 2 platforms"))
			Expect(aggregateErr.Error()).To(ContainSubstring("linux/arm64 (" + string(expectedStatus) + ")"))
			Expect(aggregateErr.Error()).NotTo(ContainSubstring("linux/amd64 ("))
		},
		Entry("missing attestation", func(ctx SpecContext) {},
			PlatformVerifyStatusMissing, "no attestation found"),
		Entry("present but unsigned legacy bare-DSSE", func(ctx SpecContext) {
			attachUnsignedBareDSSE(ctx, arm64Digest)
		}, PlatformVerifyStatusUnsigned, "legacy format"),
		Entry("signed by a different key", func(ctx SpecContext) {
			attachSignedBundle(ctx, arm64Digest, cyclonedxType, signerB)
		}, PlatformVerifyStatusInvalid, "verify DSSE signature"),
		// An attestation of another predicate kind occupies its own artifact slot,
		// so it is never returned for this query: the platform simply has no
		// cyclonedx attestation.
		Entry("only an attestation of another predicate kind", func(ctx SpecContext) {
			openvexType, err := ResolvePredicateType("openvex")
			Expect(err).NotTo(HaveOccurred())
			attachSignedBundle(ctx, arm64Digest, openvexType, signerA)
		}, PlatformVerifyStatusMissing, "no attestation found"),
	)

	It("lists every failing platform when all platforms fail verification", func(ctx SpecContext) {
		attachSignedBundle(ctx, amd64Digest, cyclonedxType, signerB)
		attachSignedBundle(ctx, arm64Digest, cyclonedxType, signerB)

		results, err := VerifyIndex(ctx, repo, indexDigest, imageName, "cyclonedx", []signature.Verifier{verifierA}, remoteOpts...)
		Expect(err).NotTo(HaveOccurred())

		aggregateErr := VerifyIndexResultError(results)
		Expect(aggregateErr).To(HaveOccurred())
		Expect(aggregateErr.Error()).To(ContainSubstring("2 of 2 platforms"))
		Expect(aggregateErr.Error()).To(ContainSubstring("linux/amd64 (invalid)"))
		Expect(aggregateErr.Error()).To(ContainSubstring("linux/arm64 (invalid)"))
	})
})

type indexEntry struct {
	digest   string
	platform *v1.Platform
}

func writeRandomImage(ctx SpecContext, repo string, remoteOpts []remote.Option) string {
	img, err := random.Image(256, 1)
	Expect(err).NotTo(HaveOccurred())

	digest, err := img.Digest()
	Expect(err).NotTo(HaveOccurred())

	ref, err := name.NewDigest(repo + "@" + digest.String())
	Expect(err).NotTo(HaveOccurred())
	Expect(remote.Write(ref, img, remoteOpts...)).To(Succeed())

	return digest.String()
}

func writeIndex(ctx SpecContext, repo string, remoteOpts []remote.Option, entries []indexEntry) string {
	index := v1.ImageIndex(empty.Index)
	for _, entry := range entries {
		ref, err := name.NewDigest(repo + "@" + entry.digest)
		Expect(err).NotTo(HaveOccurred())

		img, err := remote.Image(ref, remoteOpts...)
		Expect(err).NotTo(HaveOccurred())

		index = mutate.AppendManifests(index, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: entry.platform},
		})
	}

	digest, err := index.Digest()
	Expect(err).NotTo(HaveOccurred())

	ref, err := name.NewDigest(repo + "@" + digest.String())
	Expect(err).NotTo(HaveOccurred())
	Expect(remote.WriteIndex(ref, index, remoteOpts...)).To(Succeed())

	return digest.String()
}
