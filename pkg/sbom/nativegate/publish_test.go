package nativegate

import (
	"debug/elf"
	"encoding/json"
	"net/http/httptest"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imageMetadata "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	sbomimage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/test/pkg/signutils"
)

var _ = ginkgo.Describe("published embedded composition", func() {
	ginkgo.DescribeTable("retains composition, file edges and the image binding through the registry", func(ctx ginkgo.SpecContext, signed bool) {
		gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
		server := httptest.NewServer(registry.New())
		ginkgo.DeferCleanup(server.Close)
		repo := strings.TrimPrefix(server.URL, "http://") + "/test/embedded"
		record := fixtureBuildRecord(elf.ET_EXEC)
		record.Components = append(record.Components, shared.BuildComponent{ID: "library", Name: "library", Version: "2.3.4", Source: shared.BuildSource{Kind: "pm", Locator: "registry.example/library", Checksum: "sha256:" + strings.Repeat("a", 64)}})
		record.Inputs = append(record.Inputs, shared.BuildInput{Kind: "header", Path: "/source/lib.h", SHA256: "sha256:" + strings.Repeat("b", 64), Components: []string{"library"}, Disposition: "included"})
		app, standalone := runtimeELFWithRecord(elf.ET_EXEC, record), minimalRuntimeELF(elf.ET_EXEC)
		img := fixtureImage(map[string]string{"/app": string(app), "/standalone": string(standalone)})
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg.OS, cfg.Architecture = "linux", "amd64"
		img, err = mutate.ConfigFile(img, cfg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ref, err := name.NewTag(repo + ":image")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Write(ref, img, remote.WithContext(ctx))).To(gomega.Succeed())
		parent, err := img.Digest()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bom := cdx.NewBOM()
		bom.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, BOMRef: parent.String(), Name: repo, Version: parent.String()}}
		gomega.Expect(Apply(ctx, fixturePolicy("image"), "image", img, []*cdx.BOM{}, bom)).To(gomega.Succeed())
		cyclonedxutil.Canonicalize(ctx, bom)
		raw, err := cyclonedxutil.ToJSON(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var signer signature.Signer
		if signed {
			signer = signutils.GenerateSignerVerifier(cert_utils.KeyType_ED25519)
		}
		gomega.Expect(sbomimage.PushSBOM(ctx, raw, repo, parent.String(), "image", "fixture-policy", "linux/amd64", signer)).To(gomega.Succeed())
		downloaded, err := sbomimage.PullSBOM(ctx, repo, parent.String(), "image")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(downloaded).To(gomega.MatchJSON(raw))
		restored, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(downloaded)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		before, err := inherited([]*cdx.BOM{bom})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		after, err := inherited([]*cdx.BOM{restored})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(after).To(gomega.Equal(before))
		gomega.Expect(*restored.Dependencies).To(gomega.Equal(*bom.Dependencies))
		gomega.Expect(*restored.Components).To(gomega.Equal(*bom.Components))
		gomega.Expect(after.Records).To(gomega.HaveLen(2))
		appRef, standaloneRef, libraryRef := "", "", ""
		for _, component := range *restored.Components {
			switch component.Name {
			case "/app":
				appRef = component.BOMRef
				gomega.Expect(component.Hashes).NotTo(gomega.BeNil())
				gomega.Expect(*component.Hashes).To(gomega.ContainElement(cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: strings.TrimPrefix(digest(app), "sha256:")}))
			case "/standalone":
				standaloneRef = component.BOMRef
			case "library":
				libraryRef = component.BOMRef
				gomega.Expect(component.Version).To(gomega.Equal("2.3.4"))
			}
		}
		gomega.Expect(appRef).NotTo(gomega.BeEmpty())
		gomega.Expect(standaloneRef).NotTo(gomega.BeEmpty())
		gomega.Expect(libraryRef).NotTo(gomega.BeEmpty())
		edges := map[string][]string{}
		for _, edge := range *restored.Dependencies {
			edges[edge.Ref] = *edge.Dependencies
		}
		gomega.Expect(edges[parent.String()]).To(gomega.ConsistOf(appRef, standaloneRef))
		gomega.Expect(edges[appRef]).To(gomega.ContainElement(libraryRef))
		gomega.Expect(edges[standaloneRef]).NotTo(gomega.ContainElement(libraryRef))

		for _, file := range after.Records {
			var embedded shared.BuildRecord
			gomega.Expect(json.Unmarshal(file.Composition, &embedded)).To(gomega.Succeed())
			gomega.Expect(embedded.Complete).To(gomega.BeTrue())
			gomega.Expect(embedded.Inputs).NotTo(gomega.BeNil())
			if file.Path == "/standalone" {
				gomega.Expect(embedded.Inputs).To(gomega.BeEmpty())
			}
		}
		store := artifact.NewOCIStore(repo, "image")
		descriptor, found, err := attestation.FindAttachedArtifact(ctx, store, parent.String(), attestation.PredicateKindCycloneDX)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(descriptor.Annotations).To(gomega.HaveKeyWithValue(imageMetadata.WerfPlatformAnnotation, "linux/amd64"))
		envelope, err := attestation.PullAttestationEnvelope(ctx, store, parent.String(), sbomimage.CycloneDXPredicateTypes, attestation.PullAttestationEnvelopeOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		statement, err := sbomimage.UnwrapDSSE(envelope, attestation.InTotoMediaType)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var header in_toto.StatementHeader
		gomega.Expect(json.Unmarshal(statement, &header)).To(gomega.Succeed())
		gomega.Expect(header.Subject).To(gomega.Equal([]in_toto.Subject{{Name: repo, Digest: map[string]string{"sha256": parent.Hex}}}))
		resolved, err := artifact.ResolvePlatformDigest(ctx, repo, parent.String(), "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(resolved).To(gomega.Equal(parent.String()))
		_, err = artifact.ResolvePlatformDigest(ctx, repo, parent.String(), "linux/arm64")
		gomega.Expect(err).To(gomega.HaveOccurred())
		_, err = sbomimage.PullSBOM(ctx, repo, digest([]byte("different parent")), "image")
		gomega.Expect(err).To(gomega.HaveOccurred())
		policy := fixturePolicy("image")
		policy.Tools = nil
		gomega.Expect(Apply(ctx, policy, "image", img, []*cdx.BOM{restored}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("unregistered tool")))
	}, ginkgo.Entry("unsigned", false), ginkgo.Entry("signed", true))
})
