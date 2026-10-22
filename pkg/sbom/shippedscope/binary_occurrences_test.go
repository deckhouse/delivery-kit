package shippedscope

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("Persisted binary evidence", func() {
	var donor *cdx.BOM
	var produced *ProducedFiles
	var fileIndex *FileIndex

	ginkgo.BeforeEach(func() {
		donor = cyclonedxutil.NewBOM()
		donor.Components = &[]cdx.Component{
			componentOf("pkg:golang/example.com/one@v1.0.0"),
			componentOf("pkg:golang/example.com/two@v1.0.0"),
			componentOf("pkg:golang/example.com/test-only@v1.0.0"),
		}
		produced = &ProducedFiles{Known: true, Files: []ProducedFile{
			{Path: "/dist/one", Digest: digestOf("one"), Classification: BinaryClassification{Go: VerdictNames, Modules: []string{"example.com/one"}, Rust: VerdictNone}},
			{Path: "/dist/two", Digest: digestOf("two"), Classification: BinaryClassification{Go: VerdictNames, Modules: []string{"example.com/two"}, Rust: VerdictNone}},
		}}
		fileIndex = indexOf(map[string]File{"/renamed/one": {Digest: digestOf("one"), Size: 3}})
	})

	ginkgo.It("records actual binary paths before merging and marks only unlinked modules", func(ctx ginkgo.SpecContext) {
		PrepareBinaryOccurrences(ctx, donor, produced)
		gomega.Expect((*donor.Components)[0].Evidence).NotTo(gomega.BeNil())
		gomega.Expect(lo.FromPtr((*donor.Components)[0].Evidence.Occurrences)).To(gomega.ContainElement(cdx.EvidenceOccurrence{
			Location: "/dist/one", AdditionalContext: "werf:binary:v1:" + digestOf("one"),
		}))
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.Equal(2))
		gomega.Expect(propertyValue(&(*donor.Components)[0], PropertyShipped)).To(gomega.BeEmpty())
		gomega.Expect(propertyValue(&(*donor.Components)[1], PropertyShipped)).To(gomega.Equal("false"))
		gomega.Expect(propertyValue(&(*donor.Components)[2], PropertyShipped)).To(gomega.Equal("false"))
	})

	ginkgo.DescribeTable("survives serialization, merge, selective import and another generation", func(ctx ginkgo.SpecContext, donorFirst bool) {
		PrepareBinaryOccurrences(ctx, donor, produced)
		data, err := cyclonedxutil.ToJSON(donor)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		NormalizeInheritedBinaryOccurrences(ctx, read)
		other, err := cyclonedxutil.CloneBOM(read)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		PrepareBinaryOccurrences(ctx, other, &ProducedFiles{Known: true})
		if !donorFirst {
			read, other = other, read
		}
		merged, err := cyclonedxutil.MergeBOMs(ctx, other, cyclonedxutil.MergeOpts{BaseBOM: read})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		RecordProducedBinaryOccurrences(ctx, merged, &ProducedFiles{Known: true})
		gomega.Expect(MarkNotShipped(ctx, merged, filesetsOf(fileIndex))).To(gomega.Equal(2))
		data, err = cyclonedxutil.ToJSON(merged)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		grandchild, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		NormalizeInheritedBinaryOccurrences(ctx, grandchild)
		RecordProducedBinaryOccurrences(ctx, grandchild, &ProducedFiles{Known: true})
		gomega.Expect(MarkNotShipped(ctx, grandchild, filesetsOf(fileIndex))).To(gomega.Equal(2))
		gomega.Expect(MarkNotShipped(ctx, grandchild, filesetsOf(emptyIndex()))).To(gomega.Equal(3))
	}, ginkgo.Entry("donor first", true), ginkgo.Entry("donor last", false))

	ginkgo.DescribeTable("preserves unknown origins even beside positive and checked-empty evidence", func(ctx ginkgo.SpecContext, unknownFirst bool) {
		old, err := cyclonedxutil.CloneBOM(donor)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		NormalizeInheritedBinaryOccurrences(ctx, old)
		PrepareBinaryOccurrences(ctx, donor, produced)
		if unknownFirst {
			donor, old = old, donor
		}
		merged, err := cyclonedxutil.MergeBOMs(ctx, donor, cyclonedxutil.MergeOpts{BaseBOM: old})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		RecordProducedBinaryOccurrences(ctx, merged, &ProducedFiles{Known: true})
		gomega.Expect(MarkNotShipped(ctx, merged, filesetsOf(fileIndex))).To(gomega.BeZero())
		data, err := cyclonedxutil.ToJSON(merged)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		grandchild, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		NormalizeInheritedBinaryOccurrences(ctx, grandchild)
		gomega.Expect(MarkNotShipped(ctx, grandchild, filesetsOf(emptyIndex()))).To(gomega.BeZero())
	}, ginkgo.Entry("unknown first", true), ginkgo.Entry("unknown last", false))

	ginkgo.It("does not promote digest-bound unknown to permanent unknown through normalization", func(ctx ginkgo.SpecContext) {
		produced.Files = []ProducedFile{{Path: "/dist/opaque", Digest: digestOf("opaque"), Classification: BinaryClassification{Go: VerdictUnknown, Rust: VerdictNone}}}
		PrepareBinaryOccurrences(ctx, donor, produced)
		data, err := cyclonedxutil.ToJSON(donor)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		NormalizeInheritedBinaryOccurrences(ctx, read)
		gomega.Expect(MarkNotShipped(ctx, read, filesetsOf(indexOf(map[string]File{"/opaque": {Digest: digestOf("opaque"), Size: 6}})))).To(gomega.BeZero())
		gomega.Expect(MarkNotShipped(ctx, read, filesetsOf(emptyIndex()))).To(gomega.Equal(3))
	})

	ginkgo.DescribeTable("does not trust ordinary or malformed occurrences as binary proof", func(ctx ginkgo.SpecContext, context string) {
		donor.Components = &[]cdx.Component{componentOf("pkg:golang/example.com/one@v1.0.0", cdx.EvidenceOccurrence{Location: "/app/go.mod", AdditionalContext: context})}
		NormalizeInheritedBinaryOccurrences(ctx, donor)
		RecordProducedBinaryOccurrences(ctx, donor, &ProducedFiles{Known: true})
		gomega.Expect(propertyValue(&(*donor.Components)[0], PropertyBinaries)).To(gomega.Equal("unknown"))
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.BeZero())
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(emptyIndex()))).To(gomega.BeZero())
	},
		ginkgo.Entry("manifest hash", digestOf("one")),
		ginkgo.Entry("source without hash", ""),
		ginkgo.Entry("symlink", "symlink"),
		ginkgo.Entry("truncated binary hash", "werf:binary:v1:sha256:ab"),
		ginkgo.Entry("future format", "werf:binary:v2:"+digestOf("one")),
	)

	ginkgo.It("does not let a manifest hash hold a completely checked module", func(ctx ginkgo.SpecContext) {
		donor.Components = &[]cdx.Component{componentOf("pkg:golang/example.com/one@v1.0.0", cdx.EvidenceOccurrence{Location: "/app/go.mod", AdditionalContext: digestOf("one")})}
		PrepareBinaryOccurrences(ctx, donor, &ProducedFiles{Known: true})
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.Equal(1))
	})

	ginkgo.It("keeps unknown when none appears earlier in the property list", func(ctx ginkgo.SpecContext) {
		PrepareBinaryOccurrences(ctx, donor, &ProducedFiles{Known: true})
		for i := range *donor.Components {
			(*donor.Components)[i].Properties = &[]cdx.Property{{Name: PropertyBinaries, Value: "none"}, {Name: PropertyBinaries, Value: "unknown"}}
		}
		NormalizeInheritedBinaryOccurrences(ctx, donor)
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(emptyIndex()))).To(gomega.BeZero())
	})

	ginkgo.It("does not let malformed evidence hide behind complete evidence or none", func(ctx ginkgo.SpecContext) {
		PrepareBinaryOccurrences(ctx, donor, produced)
		for i := range *donor.Components {
			comp := &(*donor.Components)[i]
			if comp.Evidence == nil {
				comp.Evidence = &cdx.Evidence{}
			}
			comp.Evidence.Occurrences = lo.ToPtr(append(lo.FromPtr(comp.Evidence.Occurrences), cdx.EvidenceOccurrence{Location: "/broken", AdditionalContext: "werf:binary:v1:sha256:bad"}))
		}
		NormalizeInheritedBinaryOccurrences(ctx, donor)
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(emptyIndex()))).To(gomega.BeZero())
	})

	ginkgo.It("allows a child to compile dependencies of a packages-only donor", func(ctx ginkgo.SpecContext) {
		PrepareBinaryOccurrences(ctx, donor, &ProducedFiles{Known: true})
		NormalizeInheritedBinaryOccurrences(ctx, donor)
		RecordProducedBinaryOccurrences(ctx, donor, produced)
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.Equal(2))
		gomega.Expect(propertyValue(&(*donor.Components)[0], PropertyShipped)).To(gomega.BeEmpty())
	})

	ginkgo.It("keeps ecosystems independent and matches Go path but Rust name and version", func(ctx ginkgo.SpecContext) {
		donor.Components = &[]cdx.Component{
			componentOf("pkg:golang/example.com/one@v9.0.0"), componentOf("pkg:golang/example.com/missing@v1.0.0"),
			componentOf("pkg:cargo/serde@1.0.0"), componentOf("pkg:cargo/serde@2.0.0"),
		}
		produced.Files[0].Classification.Rust = VerdictNames
		produced.Files[0].Classification.Crates = []Crate{{Name: "serde", Version: "1.0.0"}}
		PrepareBinaryOccurrences(ctx, donor, produced)
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.Equal(2))
		gomega.Expect(propertyValue(&(*donor.Components)[0], PropertyShipped)).To(gomega.BeEmpty())
		gomega.Expect(propertyValue(&(*donor.Components)[2], PropertyShipped)).To(gomega.BeEmpty())
		produced.Files[0].Classification.Rust = VerdictUnknown
		PrepareBinaryOccurrences(ctx, donor, produced)
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.Equal(1))
		gomega.Expect(propertyValue(&(*donor.Components)[1], PropertyShipped)).To(gomega.Equal("false"))
	})

	ginkgo.It("never uses test binaries or incomplete indexing as negative evidence", func(ctx ginkgo.SpecContext) {
		produced.Files[0].Classification.TestBinary = true
		PrepareBinaryOccurrences(ctx, donor, produced)
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.Equal(3))
		fileIndex.Incomplete = true
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(fileIndex))).To(gomega.BeZero())
	})
})
