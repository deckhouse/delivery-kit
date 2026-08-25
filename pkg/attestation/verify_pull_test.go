package attestation

import (
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/oci/artifact"
)

var _ = Describe("Verify / Get against a registry", func() {
	const imageName = "app"

	const (
		vexUnversioned  = "https://openvex.dev/ns"
		vexVersioned    = "https://openvex.dev/ns/v0.2.0"
		sbomVersioned   = "https://cyclonedx.org/bom/v1.6"
		vexPredicateDoc = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`
		sbomDoc         = `{"bomFormat":"CycloneDX","specVersion":"1.6"}`
	)

	var (
		server       *httptest.Server
		repo         string
		parentDigest string
		signerA      signature.Signer
		verifierA    signature.Verifier
		verifierB    signature.Verifier
	)

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		repo = strings.TrimPrefix(server.URL, "http://") + "/test/app"

		parent, err := random.Image(256, 1)
		Expect(err).To(Succeed())
		parentRef, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(parentRef, parent, remote.WithContext(ctx))).To(Succeed())
		dgst, err := parent.Digest()
		Expect(err).To(Succeed())
		parentDigest = dgst.String()

		signerA, verifierA = generateKeyPair()
		_, verifierB = generateKeyPair()
	})

	AfterEach(func() {
		server.Close()
	})

	buildEnvelope := func(ctx SpecContext, predicate []byte, predicateType string, signer signature.Signer) []byte {
		digestHex, err := artifact.DigestHex(parentDigest)
		Expect(err).To(Succeed())
		stmtBytes, err := WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
		Expect(err).To(Succeed())
		envelopeJSON, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, signer)
		Expect(err).To(Succeed())
		return envelopeJSON
	}

	attachBundle := func(ctx SpecContext, predicate []byte, predicateType string, signer signature.Signer) {
		envelopeJSON := buildEnvelope(ctx, predicate, predicateType, signer)
		pubKey, err := signer.PublicKey()
		Expect(err).To(Succeed())
		bundleBytes, err := WrapInBundle(envelopeJSON, pubKey)
		Expect(err).To(Succeed())
		store := artifact.NewOCIStore(repo, imageName)
		Expect(store.Attach(ctx, parentDigest, BundleMediaType, bundleBytes, "checksum", "", predicateType)).To(Succeed())
	}

	attachDSSE := func(ctx SpecContext, predicate []byte, predicateType, annotation string) {
		envelopeJSON := buildEnvelope(ctx, predicate, predicateType, nil)
		store := artifact.NewOCIStore(repo, imageName)
		Expect(store.Attach(ctx, parentDigest, DSSEMediaType, envelopeJSON, "checksum", "", annotation)).To(Succeed())
	}

	Describe("classification", func() {
		It("verifies a signed annotated bundle with the right key and rejects a wrong key", func(ctx SpecContext) {
			attachBundle(ctx, []byte(vexPredicateDoc), vexUnversioned, signerA)

			predicate, err := Verify(ctx, repo, parentDigest, imageName, "openvex", []signature.Verifier{verifierA})
			Expect(err).To(Succeed())
			Expect(predicate).To(MatchJSON(vexPredicateDoc))

			_, err = Verify(ctx, repo, parentDigest, imageName, "openvex", []signature.Verifier{verifierB})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("signature verification failed"))
		})

		It("classifies an unsigned annotated artifact as present but unsigned", func(ctx SpecContext) {
			attachDSSE(ctx, []byte(vexPredicateDoc), vexVersioned, vexVersioned)

			_, err := Verify(ctx, repo, parentDigest, imageName, "openvex", []signature.Verifier{verifierA})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("present but unsigned (legacy format)"))
		})

		It("classifies an unsigned legacy annotation-less artifact as present but unsigned", func(ctx SpecContext) {
			attachDSSE(ctx, []byte(vexPredicateDoc), vexVersioned, "")

			_, err := Verify(ctx, repo, parentDigest, imageName, "openvex", []signature.Verifier{verifierA})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("present but unsigned (legacy format)"))
		})

		It("reports a missing attestation as not found", func(ctx SpecContext) {
			_, err := Verify(ctx, repo, parentDigest, imageName, "openvex", []signature.Verifier{verifierA})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(artifact.ErrNotFound))
		})
	})

	Describe("legacy kind attribution", func() {
		It("reads a legacy annotation-less VEX artifact for the openvex kind", func(ctx SpecContext) {
			attachDSSE(ctx, []byte(vexPredicateDoc), vexVersioned, "")

			predicate, err := Get(ctx, repo, parentDigest, imageName, "openvex")
			Expect(err).To(Succeed())
			Expect(predicate).To(MatchJSON(vexPredicateDoc))
		})

		It("never returns a legacy SBOM artifact for an openvex query", func(ctx SpecContext) {
			attachDSSE(ctx, []byte(sbomDoc), sbomVersioned, "")

			_, err := Get(ctx, repo, parentDigest, imageName, "openvex")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(artifact.ErrNotFound))
		})

		It("keeps SBOM and VEX artifacts independently readable on one digest", func(ctx SpecContext) {
			attachDSSE(ctx, []byte(sbomDoc), sbomVersioned, sbomVersioned)
			attachDSSE(ctx, []byte(vexPredicateDoc), vexVersioned, vexVersioned)

			vexPredicate, err := Get(ctx, repo, parentDigest, imageName, "openvex")
			Expect(err).To(Succeed())
			Expect(vexPredicate).To(MatchJSON(vexPredicateDoc))

			sbomPredicate, err := Get(ctx, repo, parentDigest, imageName, sbomVersioned)
			Expect(err).To(Succeed())
			Expect(sbomPredicate).To(MatchJSON(sbomDoc))
		})

		It("accepts both openvex predicate URIs for the openvex type", func(ctx SpecContext) {
			attachBundle(ctx, []byte(vexPredicateDoc), vexUnversioned, signerA)

			predicate, err := Get(ctx, repo, parentDigest, imageName, vexVersioned)
			Expect(err).To(Succeed())
			Expect(predicate).To(MatchJSON(vexPredicateDoc))
		})
	})
})
