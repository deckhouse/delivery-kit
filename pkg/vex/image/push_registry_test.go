package image_test

import (
	"net/http/httptest"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
	veximage "github.com/werf/werf/v2/pkg/vex/image"
	"github.com/werf/werf/v2/test/pkg/signutils"
)

var _ = Describe("PushVEX against a registry", func() {
	const imageName = "app"

	vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)

	var (
		server       *httptest.Server
		repo         string
		parentDigest string
		signer       signature.Signer
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

		signer = signutils.GenerateSignerVerifier(cert_utils.KeyType_ED25519)
	})

	AfterEach(func() {
		server.Close()
	})

	It("publishes the legacy unsigned form with the predicate annotation", func(ctx SpecContext) {
		Expect(veximage.PushVEX(ctx, vexJSON, repo, parentDigest, imageName, "checksum-v1", "", nil)).To(Succeed())

		store := artifact.NewOCIStore(repo, imageName)
		desc, found, err := store.GetAttached(ctx, parentDigest, vex.DSSEMediaType, vex.VEXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
		Expect(desc.ArtifactType).To(Equal(vex.DSSEMediaType))
		Expect(desc.Annotations[artifact.PredicateTypeAnnotation]).To(Equal(vex.VEXPredicateURI))

		envelopeJSON, err := store.GetContentByDigest(ctx, desc.Digest.String())
		Expect(err).To(Succeed())
		Expect(attestation.HasSignatures(envelopeJSON)).To(BeFalse())

		foundType, err := attestation.StatementPredicateType(envelopeJSON)
		Expect(err).To(Succeed())
		Expect(foundType).To(Equal(vex.VEXPredicateURI))
	})

	It("publishes a signed bundle superseding the unsigned artifact", func(ctx SpecContext) {
		Expect(veximage.PushVEX(ctx, vexJSON, repo, parentDigest, imageName, "checksum-v1", "", nil)).To(Succeed())
		Expect(veximage.PushVEX(ctx, vexJSON, repo, parentDigest, imageName, "checksum-v2", "", signer)).To(Succeed())

		store := artifact.NewOCIStore(repo, imageName)

		desc, found, err := store.GetAttached(ctx, parentDigest, attestation.BundleMediaType, vex.VEXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
		Expect(desc.Annotations[artifact.PredicateTypeAnnotation]).To(Equal(vex.VEXPredicateURIUnversioned))

		content, err := store.GetContentByDigest(ctx, desc.Digest.String())
		Expect(err).To(Succeed())
		envelopeJSON, err := attestation.UnwrapBundle(content)
		Expect(err).To(Succeed())
		Expect(attestation.HasSignatures(envelopeJSON)).To(BeTrue())

		_, found, err = store.GetAttached(ctx, parentDigest, vex.DSSEMediaType, vex.VEXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeFalse())
	})

	It("downgrades to the unsigned form superseding the bundle when the key is removed", func(ctx SpecContext) {
		Expect(veximage.PushVEX(ctx, vexJSON, repo, parentDigest, imageName, "checksum-v2", "", signer)).To(Succeed())
		Expect(veximage.PushVEX(ctx, vexJSON, repo, parentDigest, imageName, "checksum-v3", "", nil)).To(Succeed())

		store := artifact.NewOCIStore(repo, imageName)
		_, found, err := store.GetAttached(ctx, parentDigest, attestation.BundleMediaType, vex.VEXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeFalse())

		desc, found, err := store.GetAttached(ctx, parentDigest, vex.DSSEMediaType, vex.VEXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
		Expect(desc.Annotations[artifact.PredicateTypeAnnotation]).To(Equal(vex.VEXPredicateURI))
	})

	It("supersedes a legacy annotation-less VEX artifact of its own kind only", func(ctx SpecContext) {
		legacyEnvelope := buildLegacyEnvelope(ctx, vexJSON, vex.VEXPredicateURI, repo, parentDigest)
		legacySbomEnvelope := buildLegacyEnvelope(ctx, []byte(`{"bomFormat":"CycloneDX"}`), "https://cyclonedx.org/bom/v1.6", repo, parentDigest)

		vexStore := artifact.NewOCIStore(repo, imageName)
		Expect(vexStore.Attach(ctx, parentDigest, vex.DSSEMediaType, legacyEnvelope, "legacy-checksum", "", "")).To(Succeed())

		sbomStore := artifact.NewOCIStore(repo, "other-app")
		Expect(sbomStore.Attach(ctx, parentDigest, vex.DSSEMediaType, legacySbomEnvelope, "legacy-sbom-checksum", "", "")).To(Succeed())

		Expect(veximage.PushVEX(ctx, vexJSON, repo, parentDigest, imageName, "checksum-v2", "", nil)).To(Succeed())

		_, found, err := vexStore.GetAttachedLegacy(ctx, parentDigest, vex.DSSEMediaType)
		Expect(err).To(Succeed())
		Expect(found).To(BeFalse())

		_, found, err = sbomStore.GetAttachedLegacy(ctx, parentDigest, vex.DSSEMediaType)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
	})
})

func buildLegacyEnvelope(ctx SpecContext, predicate []byte, predicateType, repo, parentDigest string) []byte {
	digestHex, err := artifact.DigestHex(parentDigest)
	Expect(err).To(Succeed())
	stmtBytes, err := attestation.WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
	Expect(err).To(Succeed())
	envelopeJSON, err := attestation.WrapInDSSE(ctx, stmtBytes, vex.InTotoMediaType, nil)
	Expect(err).To(Succeed())
	return envelopeJSON
}
