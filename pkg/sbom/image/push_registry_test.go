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

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	sbomimage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/test/pkg/signutils"
)

var _ = Describe("PushSBOM against a registry", func() {
	const imageName = "app"

	signedBOM := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"signed"}]}`)
	unsignedBOM := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"unsigned"}]}`)

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

	It("publishes a signed bundle superseding the unsigned artifact", func(ctx SpecContext) {
		Expect(sbomimage.PushSBOM(ctx, unsignedBOM, repo, parentDigest, imageName, "checksum-v1", "", nil)).To(Succeed())
		Expect(sbomimage.PushSBOM(ctx, signedBOM, repo, parentDigest, imageName, "checksum-v2", "", signer)).To(Succeed())

		store := artifact.NewOCIStore(repo, imageName)
		_, found, err := store.GetAttached(ctx, parentDigest, attestation.DSSEMediaType, sbomimage.CycloneDXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeFalse())

		bomJSON, err := sbomimage.PullSBOM(ctx, repo, parentDigest, imageName)
		Expect(err).To(Succeed())
		Expect(bomJSON).To(MatchJSON(signedBOM))
	})

	It("downgrades to the unsigned form superseding the bundle when the key is removed", func(ctx SpecContext) {
		Expect(sbomimage.PushSBOM(ctx, signedBOM, repo, parentDigest, imageName, "checksum-v1", "", signer)).To(Succeed())
		Expect(sbomimage.PushSBOM(ctx, unsignedBOM, repo, parentDigest, imageName, "checksum-v2", "", nil)).To(Succeed())

		store := artifact.NewOCIStore(repo, imageName)
		_, found, err := store.GetAttached(ctx, parentDigest, attestation.BundleMediaType, sbomimage.CycloneDXPredicateTypes)
		Expect(err).To(Succeed())
		Expect(found).To(BeFalse())

		desc, found, err := attestation.FindAttachedArtifact(ctx, store, parentDigest, attestation.PredicateKindCycloneDX)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
		Expect(desc.ArtifactType).To(Equal(attestation.DSSEMediaType))

		bomJSON, err := sbomimage.PullSBOM(ctx, repo, parentDigest, imageName)
		Expect(err).To(Succeed())
		Expect(bomJSON).To(MatchJSON(unsignedBOM))
	})

	It("leaves the VEX artifact of the same image alone", func(ctx SpecContext) {
		vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)
		Expect(attestation.PublishAttestation(ctx, attestation.PredicateKindOpenVEX, vexJSON, repo, parentDigest, imageName, attestation.PublishAttestationOptions{
			Signer:   signer,
			Checksum: "vex-checksum",
		})).To(Succeed())

		Expect(sbomimage.PushSBOM(ctx, unsignedBOM, repo, parentDigest, imageName, "checksum-v1", "", nil)).To(Succeed())

		store := artifact.NewOCIStore(repo, imageName)
		_, found, err := store.GetAttached(ctx, parentDigest, attestation.BundleMediaType, attestation.PredicateKindOpenVEX.Types())
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
	})
})
