package attestation

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = Describe("CopySupersededKeys", func() {
	key := func(artifactType, predicateType string) artifact.Key {
		return artifact.Key{ArtifactType: artifactType, PredicateType: predicateType}
	}

	DescribeTable("slots a copied artifact replaces at the destination",
		func(copied artifact.Key, srcSlots, expected []artifact.Key) {
			Expect(CopySupersededKeys(copied, srcSlots)).To(ConsistOf(expected))
		},
		Entry("unsigned SBOM replaces the bundle slots of its kind",
			key(DSSEMediaType, PredicateKindCycloneDX.UnsignedType),
			[]artifact.Key{key(DSSEMediaType, PredicateKindCycloneDX.UnsignedType)},
			[]artifact.Key{
				key(BundleMediaType, PredicateKindCycloneDX.SignedType),
				key(BundleMediaType, PredicateKindCycloneDX.UnsignedType),
			},
		),
		Entry("signed SBOM replaces the bare-DSSE slots of its kind",
			key(BundleMediaType, PredicateKindCycloneDX.SignedType),
			[]artifact.Key{key(BundleMediaType, PredicateKindCycloneDX.SignedType)},
			[]artifact.Key{
				key(DSSEMediaType, PredicateKindCycloneDX.SignedType),
				key(DSSEMediaType, PredicateKindCycloneDX.UnsignedType),
			},
		),
		Entry("unsigned VEX replaces the bundle slots of its kind",
			key(DSSEMediaType, PredicateKindOpenVEX.UnsignedType),
			[]artifact.Key{key(DSSEMediaType, PredicateKindOpenVEX.UnsignedType)},
			[]artifact.Key{
				key(BundleMediaType, PredicateKindOpenVEX.SignedType),
				key(BundleMediaType, PredicateKindOpenVEX.UnsignedType),
			},
		),
		Entry("a slot the source still holds is kept",
			key(DSSEMediaType, PredicateKindCycloneDX.UnsignedType),
			[]artifact.Key{
				key(DSSEMediaType, PredicateKindCycloneDX.UnsignedType),
				key(BundleMediaType, PredicateKindCycloneDX.SignedType),
			},
			[]artifact.Key{key(BundleMediaType, PredicateKindCycloneDX.UnsignedType)},
		),
		Entry("a signed VEX bundle replaces the unsigned slots of its kind",
			key(BundleMediaType, PredicateKindOpenVEX.SignedType),
			[]artifact.Key{key(BundleMediaType, PredicateKindOpenVEX.SignedType)},
			[]artifact.Key{
				key(DSSEMediaType, PredicateKindOpenVEX.SignedType),
				key(DSSEMediaType, PredicateKindOpenVEX.UnsignedType),
			},
		),

		Entry("an artifact of one kind never replaces another kind",
			key(DSSEMediaType, PredicateKindOpenVEX.UnsignedType),
			[]artifact.Key{
				key(DSSEMediaType, PredicateKindOpenVEX.UnsignedType),
				key(BundleMediaType, PredicateKindCycloneDX.SignedType),
			},
			[]artifact.Key{
				key(BundleMediaType, PredicateKindOpenVEX.SignedType),
				key(BundleMediaType, PredicateKindOpenVEX.UnsignedType),
			},
		),
		Entry("a legacy annotation-less artifact replaces nothing",
			key(DSSEMediaType, ""),
			nil,
			nil,
		),
		Entry("an artifact of an unknown kind replaces nothing",
			key(DSSEMediaType, "https://slsa.dev/provenance/v1"),
			nil,
			nil,
		),
		Entry("an artifact of an unknown type replaces nothing",
			key("application/vnd.oci.image.manifest.v1+json", PredicateKindCycloneDX.SignedType),
			nil,
			nil,
		),
	)
})
