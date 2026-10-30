package shippedscope

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = Describe("MarkNotShipped", func() {
	componentOf := func(purl string, occurrences ...cdx.EvidenceOccurrence) cdx.Component {
		comp := cdx.Component{BOMRef: purl, Name: purl, PackageURL: purl}
		if occurrences != nil {
			comp.Evidence = &cdx.Evidence{Occurrences: &occurrences}
		}

		return comp
	}

	bomOf := func(components ...cdx.Component) *cdx.BOM {
		return &cdx.BOM{Components: &components}
	}

	fileOccurrence := func(path, body string) cdx.EvidenceOccurrence {
		return cdx.EvidenceOccurrence{Location: path, AdditionalContext: digestOf(body)}
	}

	shippedProperty := func(bom *cdx.BOM, index int) (string, bool) {
		for _, property := range lo.FromPtr((*bom.Components)[index].Properties) {
			if property.Name == PropertyShipped {
				return property.Value, true
			}
		}

		return "", false
	}

	filesetsOf := func(index *FileIndex) *Filesets {
		return &Filesets{Index: index}
	}

	It("marks a component whose declared files are not in the image", func(ctx SpecContext) {
		bom := bomOf(
			componentOf("pkg:pypi/present@1.0.0", fileOccurrence("/app/present.py", "here")),
			componentOf("pkg:pypi/gone@2.0.0", fileOccurrence("/app/gone.py", "elsewhere")),
		)

		marked := MarkNotShipped(ctx, bom, filesetsOf(indexOf(map[string]File{
			"/app/present.py": {Digest: digestOf("here"), Size: 4},
		})))

		Expect(marked).To(Equal(1))
		_, present := shippedProperty(bom, 0)
		Expect(present).To(BeFalse(), "a component the image ships carries no property")
		value, found := shippedProperty(bom, 1)
		Expect(found).To(BeTrue())
		Expect(value).To(Equal("false"))
	})

	It("marks a component whose files were looked for and none were found", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:pypi/gone@2.0.0"))
		(*bom.Components)[0].Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{}}

		marked := MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))

		Expect(marked).To(Equal(1))
		value, found := shippedProperty(bom, 0)
		Expect(found).To(BeTrue())
		Expect(value).To(Equal("false"))
	})

	It("marks a component a donor looked for and did not find", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:pypi/gone@2.0.0"))
		setProperty(&(*bom.Components)[0], PropertyFiles, PropertyFilesNone)

		marked := MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))

		Expect(marked).To(Equal(1), "the donor wrote what an empty occurrence list could not carry across a serialization")
		value, found := shippedProperty(bom, 0)
		Expect(found).To(BeTrue())
		Expect(value).To(Equal("false"))
	})

	DescribeTable("preserves checked-empty evidence through a document merge",
		func(ctx SpecContext, knownFiles, donorFirst bool) {
			const purl = "pkg:pypi/requests@2.32.3"
			donor := bomOf(componentOf(purl))
			donor.SpecVersion = cdx.SpecVersion1_6
			Expect(RecordOccurrences(donor, []Fileset{{
				Ecosystem: EcosystemPython, Name: "requests", Version: "2.32.3", DeclaresFiles: true,
			}})).To(Equal(1))

			occurrence := cdx.EvidenceOccurrence{Location: "/app/requirements.txt"}
			if knownFiles {
				occurrence = fileOccurrence("/original/requests.py", "requests")
			}
			other := bomOf(componentOf(purl, occurrence))
			other.SpecVersion = cdx.SpecVersion1_6
			if !donorFirst {
				donor, other = other, donor
			}

			merged, err := cyclonedxutil.MergeBOMs(ctx, other, cyclonedxutil.MergeOpts{BaseBOM: donor})
			Expect(err).NotTo(HaveOccurred())
			data, err := cyclonedxutil.ToJSON(merged)
			Expect(err).NotTo(HaveOccurred())
			read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
			Expect(err).NotTo(HaveOccurred())
			Expect(*read.Components).To(HaveLen(1))

			marked := MarkNotShipped(ctx, read, filesetsOf(indexOf(map[string]File{
				"/relocated/requests.py": {Digest: digestOf("requests"), Size: 8},
			})))
			if knownFiles {
				Expect(marked).To(BeZero(), "actual file evidence takes precedence over a donor's empty verdict")
				_, found := shippedProperty(read, 0)
				Expect(found).To(BeFalse())
			} else {
				Expect(marked).To(Equal(1), "scanner-only evidence must not erase the checked-empty verdict")
				value, found := shippedProperty(read, 0)
				Expect(found).To(BeTrue())
				Expect(value).To(Equal("false"))
			}
		},
		Entry("scanner evidence after the donor", false, true),
		Entry("scanner evidence before the donor", false, false),
		Entry("file evidence after the donor", true, true),
		Entry("file evidence before the donor", true, false),
	)

	It("keeps a component nothing is known about", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:pypi/unknown@1.0.0"))

		marked := MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))

		Expect(marked).To(BeZero())
		_, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse())
	})

	It("keeps a component whose only occurrences came from elsewhere", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:pypi/scanned@1.0.0",
			cdx.EvidenceOccurrence{Location: "/app/scanned.py"},
			cdx.EvidenceOccurrence{Location: "/app/other.py", AdditionalContext: "seen by a scanner"},
		))

		marked := MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))

		Expect(marked).To(BeZero())
		_, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse())
	})

	It("finds a component by content wherever an import put it", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:generic/jq@1.8.1", fileOccurrence("/usr/bin/jq", "jq")))

		marked := MarkNotShipped(ctx, bom, filesetsOf(indexOf(map[string]File{
			"/bin/jq": {Digest: digestOf("jq"), Size: 2},
		})))

		Expect(marked).To(BeZero())
		_, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse())
	})

	It("keeps every os-pm component when the image records no file lists", func(ctx SpecContext) {
		bom := bomOf(
			componentOf("pkg:generic/gone@1.0.0", fileOccurrence("/usr/lib/gone.so", "gone")),
			componentOf("pkg:pypi/gone@2.0.0", fileOccurrence("/app/gone.py", "gone too")),
		)

		filesets := filesetsOf(emptyIndex())
		filesets.OSPMFileListMissing = true

		marked := MarkNotShipped(ctx, bom, filesets)

		Expect(marked).To(Equal(1), "only the component of an ecosystem the image does describe is judged")
		_, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse())
		_, found = shippedProperty(bom, 1)
		Expect(found).To(BeTrue())
	})

	It("keeps a Go module, whose binaries this image's produced set does not cover", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:golang/github.com/spf13/cobra@1.8.0"))

		marked := MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))

		Expect(marked).To(BeZero())
		_, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse())
	})

	It("marks a nested component", func(ctx SpecContext) {
		nested := []cdx.Component{componentOf("pkg:pypi/gone@2.0.0", fileOccurrence("/app/gone.py", "gone"))}
		outer := componentOf("pkg:pypi/outer@1.0.0", fileOccurrence("/app/outer.py", "outer"))
		outer.Components = &nested

		bom := bomOf(outer)

		marked := MarkNotShipped(ctx, bom, filesetsOf(indexOf(map[string]File{
			"/app/outer.py": {Digest: digestOf("outer"), Size: 5},
		})))

		Expect(marked).To(Equal(1))
		value, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse(), "the outer component ships")
		Expect(value).To(BeEmpty())

		for _, property := range lo.FromPtr((*(*bom.Components)[0].Components)[0].Properties) {
			if property.Name == PropertyShipped {
				Expect(property.Value).To(Equal("false"))

				return
			}
		}
		Fail("the nested component carries no shipped property")
	})

	It("clears a verdict a donor recorded when this image does ship the component", func(ctx SpecContext) {
		comp := componentOf("pkg:pypi/present@1.0.0", fileOccurrence("/app/present.py", "here"))
		comp.Properties = &[]cdx.Property{{Name: PropertyShipped, Value: "false"}}

		bom := bomOf(comp)

		marked := MarkNotShipped(ctx, bom, filesetsOf(indexOf(map[string]File{
			"/app/present.py": {Digest: digestOf("here"), Size: 4},
		})))

		Expect(marked).To(BeZero())
		_, found := shippedProperty(bom, 0)
		Expect(found).To(BeFalse(), "the donor's verdict describes the donor's image, not this one")
	})

	// Of the ecosystems whose files this image can describe, a donor's verdict goes
	// whether or not a new one replaces it: this image looked, and what it saw is the
	// only thing its own SBOM may state.
	It("clears a verdict a donor recorded on a component of an ecosystem it judges", func(ctx SpecContext) {
		module := componentOf("pkg:golang/github.com/spf13/cobra@1.8.0")
		module.Properties = &[]cdx.Property{{Name: PropertyShipped, Value: "false"}}
		osPM := componentOf("pkg:generic/zlib@1.3.1", fileOccurrence("/usr/lib/libz.so", "z"))
		osPM.Properties = &[]cdx.Property{{Name: PropertyShipped, Value: "false"}}

		bom := bomOf(module, osPM)

		filesets := filesetsOf(emptyIndex())
		filesets.OSPMFileListMissing = true

		Expect(MarkNotShipped(ctx, bom, filesets)).To(BeZero())
		for i := range *bom.Components {
			_, found := shippedProperty(bom, i)
			Expect(found).To(BeFalse(), "component %d keeps a verdict this image never made", i)
		}
	})

	// A deb package is of no ecosystem whose files this pass reads, so it has nothing to
	// put in place of the verdict the component already carries. Dropping it would leave
	// the component saying less than somebody knew, and would be this image claiming to
	// have looked where it never did.
	It("leaves a verdict standing on a component of an ecosystem it does not judge", func(ctx SpecContext) {
		deb := componentOf("pkg:deb/debian/libc6@2.36")
		deb.Properties = &[]cdx.Property{{Name: PropertyShipped, Value: "false"}}

		bom := bomOf(deb)

		Expect(MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))).To(BeZero())

		value, found := shippedProperty(bom, 0)
		Expect(found).To(BeTrue())
		Expect(value).To(Equal("false"))
	})

	It("leaves the component's other properties alone", func(ctx SpecContext) {
		comp := componentOf("pkg:pypi/present@1.0.0", fileOccurrence("/app/present.py", "here"))
		comp.Properties = &[]cdx.Property{
			{Name: "werf:package:foundBy", Value: "pip"},
			{Name: PropertyShipped, Value: "false"},
		}

		bom := bomOf(comp)

		MarkNotShipped(ctx, bom, filesetsOf(indexOf(map[string]File{
			"/app/present.py": {Digest: digestOf("here"), Size: 4},
		})))

		Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(Equal([]cdx.Property{
			{Name: "werf:package:foundBy", Value: "pip"},
		}))
	})

	It("replaces a property the component already carries", func(ctx SpecContext) {
		comp := componentOf("pkg:pypi/gone@2.0.0", fileOccurrence("/app/gone.py", "gone"))
		comp.Properties = &[]cdx.Property{
			{Name: "werf:package:foundBy", Value: "pm"},
			{Name: PropertyShipped, Value: "true"},
		}

		bom := bomOf(comp)

		Expect(MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))).To(Equal(1))
		Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(HaveLen(2))
		value, found := shippedProperty(bom, 0)
		Expect(found).To(BeTrue())
		Expect(value).To(Equal("false"))
	})

	It("does nothing without an index of the image", func(ctx SpecContext) {
		bom := bomOf(componentOf("pkg:pypi/gone@2.0.0", fileOccurrence("/app/gone.py", "gone")))

		Expect(MarkNotShipped(ctx, bom, &Filesets{})).To(BeZero())
		Expect((*bom.Components)[0].Properties).To(BeNil())
	})
})
