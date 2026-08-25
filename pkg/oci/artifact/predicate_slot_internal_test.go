package artifact

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
)

const (
	testDSSEType   = "application/vnd.dsse.envelope.v1+json"
	testBundleType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	sbomPredicate       = "https://cyclonedx.org/bom"
	sbomLegacyPredicate = "https://cyclonedx.org/bom/v1.6"
	vexPredicate        = "https://openvex.dev/ns"
	vexLegacyPredicate  = "https://openvex.dev/ns/v0.2.0"
)

func predicateDesc(name, artifactType, imageName, predicateType string) v1.Descriptor {
	annotations := map[string]string{}
	if imageName != "" {
		annotations[image.WerfImageNameAnnotation] = imageName
	}
	if predicateType != "" {
		annotations[PredicateTypeAnnotation] = predicateType
	}
	return v1.Descriptor{
		MediaType:    types.OCIManifestSchema1,
		Digest:       digestForName(name),
		Size:         42,
		ArtifactType: artifactType,
		Annotations:  annotations,
	}
}

var _ = Describe("predicate slot discrimination", func() {
	Describe("updateFallbackIndex", func() {
		DescribeTable("coexistence: attaching one kind never evicts another kind",
			func(existing, attached v1.Descriptor, attachedPredicate string) {
				idx := newStaticIndex([]v1.Descriptor{existing})
				idx = updateFallbackIndex(idx, attached, attached.ArtifactType, "app", attachedPredicate, nil)

				im, err := idx.IndexManifest()
				Expect(err).To(Succeed())
				Expect(im.Manifests).To(HaveLen(2))
			},
			Entry("unsigned VEX next to unsigned SBOM (same artifactType)",
				predicateDesc("sbom-dsse", testDSSEType, "app", sbomLegacyPredicate),
				predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate),
				vexLegacyPredicate),
			Entry("signed VEX next to signed SBOM (same artifactType)",
				predicateDesc("sbom-bundle", testBundleType, "app", sbomPredicate),
				predicateDesc("vex-bundle", testBundleType, "app", vexPredicate),
				vexPredicate),
			Entry("annotated VEX next to a legacy annotation-less entry",
				predicateDesc("legacy", testDSSEType, "app", ""),
				predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate),
				vexLegacyPredicate),
			Entry("legacy-slot writer next to an annotated entry of another kind",
				predicateDesc("sbom-dsse", testDSSEType, "app", sbomLegacyPredicate),
				predicateDesc("legacy", testDSSEType, "app", ""),
				""),
		)

		It("replaces the entry of its own slot only", func() {
			sbom := predicateDesc("sbom-dsse", testDSSEType, "app", sbomLegacyPredicate)
			staleVex := predicateDesc("vex-v1", testDSSEType, "app", vexLegacyPredicate)
			idx := newStaticIndex([]v1.Descriptor{sbom, staleVex})

			freshVex := predicateDesc("vex-v2", testDSSEType, "app", vexLegacyPredicate)
			idx = updateFallbackIndex(idx, freshVex, testDSSEType, "app", vexLegacyPredicate, nil)

			im, err := idx.IndexManifest()
			Expect(err).To(Succeed())
			Expect(im.Manifests).To(HaveLen(2))
			digests := []v1.Hash{im.Manifests[0].Digest, im.Manifests[1].Digest}
			Expect(digests).To(ContainElements(sbom.Digest, freshVex.Digest))
		})

		It("supersedes the listed keys of its own kind across artifact types", func() {
			sbomBundle := predicateDesc("sbom-bundle", testBundleType, "app", sbomPredicate)
			staleVexDSSE := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)
			legacyVex := predicateDesc("legacy-vex", testDSSEType, "app", "")
			idx := newStaticIndex([]v1.Descriptor{sbomBundle, staleVexDSSE, legacyVex})

			signedVex := predicateDesc("vex-bundle", testBundleType, "app", vexPredicate)
			superseded := []Key{
				{ArtifactType: testDSSEType, PredicateType: vexPredicate},
				{ArtifactType: testDSSEType, PredicateType: vexLegacyPredicate},
				{ArtifactType: testDSSEType, PredicateType: ""},
			}
			idx = updateFallbackIndex(idx, signedVex, testBundleType, "app", vexPredicate, superseded)

			im, err := idx.IndexManifest()
			Expect(err).To(Succeed())
			Expect(im.Manifests).To(HaveLen(2))
			digests := []v1.Hash{im.Manifests[0].Digest, im.Manifests[1].Digest}
			Expect(digests).To(ContainElements(sbomBundle.Digest, signedVex.Digest))
		})

		It("keeps a legacy entry not listed as superseded", func() {
			legacy := predicateDesc("legacy", testDSSEType, "app", "")
			idx := newStaticIndex([]v1.Descriptor{legacy})

			signedVex := predicateDesc("vex-bundle", testBundleType, "app", vexPredicate)
			idx = updateFallbackIndex(idx, signedVex, testBundleType, "app", vexPredicate, []Key{
				{ArtifactType: testDSSEType, PredicateType: vexPredicate},
				{ArtifactType: testDSSEType, PredicateType: vexLegacyPredicate},
			})

			im, err := idx.IndexManifest()
			Expect(err).To(Succeed())
			Expect(im.Manifests).To(HaveLen(2))
		})
	})

	Describe("isAttached", func() {
		It("treats entries of another predicate kind as free slots", func() {
			sbom := predicateDesc("sbom-dsse", testDSSEType, "app", sbomLegacyPredicate)
			target := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)

			im, err := newStaticIndex([]v1.Descriptor{sbom, target}).IndexManifest()
			Expect(err).To(Succeed())
			Expect(isAttached(im, target, testDSSEType, "app", vexLegacyPredicate, nil)).To(BeTrue())
		})

		It("is not satisfied while a superseded key is still present", func() {
			stale := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)
			target := predicateDesc("vex-bundle", testBundleType, "app", vexPredicate)

			im, err := newStaticIndex([]v1.Descriptor{stale, target}).IndexManifest()
			Expect(err).To(Succeed())
			Expect(isAttached(im, target, testBundleType, "app", vexPredicate, []Key{
				{ArtifactType: testDSSEType, PredicateType: vexLegacyPredicate},
			})).To(BeFalse())
		})
	})

	Describe("matchDescriptors", func() {
		It("prefers annotated matches and appends legacy candidates last", func() {
			legacy := predicateDesc("legacy", testDSSEType, "app", "")
			annotated := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)

			im, err := newStaticIndex([]v1.Descriptor{legacy, annotated}).IndexManifest()
			Expect(err).To(Succeed())

			matches := matchDescriptors(im, testDSSEType, "app", []string{vexPredicate, vexLegacyPredicate})
			Expect(matches).To(HaveLen(2))
			Expect(matches[0].Digest).To(Equal(annotated.Digest))
			Expect(matches[1].Digest).To(Equal(legacy.Digest))
		})

		It("excludes entries annotated with another predicate kind", func() {
			sbom := predicateDesc("sbom-dsse", testDSSEType, "app", sbomLegacyPredicate)
			vexEntry := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)

			im, err := newStaticIndex([]v1.Descriptor{sbom, vexEntry}).IndexManifest()
			Expect(err).To(Succeed())

			matches := matchDescriptors(im, testDSSEType, "app", []string{vexPredicate, vexLegacyPredicate})
			Expect(matches).To(HaveLen(1))
			Expect(matches[0].Digest).To(Equal(vexEntry.Digest))
		})

		It("returns every entry when no predicate filter is given", func() {
			sbom := predicateDesc("sbom-dsse", testDSSEType, "app", sbomLegacyPredicate)
			vexEntry := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)
			legacy := predicateDesc("legacy", testDSSEType, "app", "")

			im, err := newStaticIndex([]v1.Descriptor{sbom, vexEntry, legacy}).IndexManifest()
			Expect(err).To(Succeed())

			Expect(matchDescriptors(im, testDSSEType, "app", nil)).To(HaveLen(3))
		})

		It("deduplicates the go-containerregistry auto entry against the annotated one", func() {
			annotated := predicateDesc("vex-dsse", testDSSEType, "app", vexLegacyPredicate)
			auto := v1.Descriptor{
				MediaType:    types.OCIManifestSchema1,
				Digest:       annotated.Digest,
				Size:         42,
				ArtifactType: testDSSEType,
			}

			im, err := newStaticIndex([]v1.Descriptor{auto, annotated}).IndexManifest()
			Expect(err).To(Succeed())

			matches := matchDescriptors(im, testDSSEType, "", []string{vexPredicate, vexLegacyPredicate})
			Expect(matches).To(HaveLen(1))
			Expect(matches[0].Annotations[PredicateTypeAnnotation]).To(Equal(vexLegacyPredicate))
		})
	})
})
