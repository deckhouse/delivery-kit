package shippedscope

import (
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = Describe("Editable Python evidence", func() {
	DescribeTable("recognizes editable or unclassifiable origin metadata without executing hooks",
		func(ctx SpecContext, origin, record string, wantUnknown bool) {
			entries := []tarEntry{
				regularFile("site/pkg-1.0.dist-info/RECORD", record),
				regularFile("site/pkg.py", "payload"),
				regularFile("site/generic.pth", "import arbitrary_code\n"),
			}
			if origin != "" {
				entries = append(entries, regularFile("site/pkg-1.0.dist-info/direct_url.json", origin))
			}
			image, err := imageOf(entries)
			Expect(err).NotTo(HaveOccurred())
			filesets, err := CollectFilesets(ctx, image)
			Expect(err).NotTo(HaveOccurred())
			set := filesetOf(filesets, EcosystemPython, "pkg", "1.0")
			Expect(set).NotTo(BeNil())
			Expect(set.Incomplete).To(Equal(wantUnknown))
			bom := cyclonedxutil.NewBOM()
			bom.Components = &[]cdx.Component{{PackageURL: "pkg:pypi/pkg@1.0"}}
			RecordOccurrences(bom, filesets.Filesets)
			Expect(incompleteFileEvidence(&(*bom.Components)[0])).To(Equal(wantUnknown))
		},
		Entry("PEP 660 without a pth", `{"dir_info":{"editable":true}}`, "pkg.py,,\n", true),
		Entry("editable with an empty RECORD", `{"dir_info":{"editable":true}}`, "", true),
		Entry("malformed origin", `{`, "pkg.py,,\n", true),
		Entry("null origin", `null`, "pkg.py,,\n", true),
		Entry("non-object origin", `[]`, "pkg.py,,\n", true),
		Entry("non-object directory", `{"dir_info":true}`, "pkg.py,,\n", true),
		Entry("null directory", `{"dir_info":null}`, "pkg.py,,\n", true),
		Entry("string editable is not boolean false", `{"dir_info":{"editable":"false"}}`, "pkg.py,,\n", true),
		Entry("null editable is not boolean false", `{"dir_info":{"editable":null}}`, "pkg.py,,\n", true),
		Entry("ordinary install with a pth", `{"dir_info":{"editable":false}}`, "pkg.py,,\ngeneric.pth,,\n", false),
		Entry("omitted editable defaults to false", `{"dir_info":{}}`, "pkg.py,,\n", false),
		Entry("VCS origin is not editable", `{"vcs_info":{"vcs":"git","commit_id":"abc"}}`, "pkg.py,,\n", false),
		Entry("normal wheel has no origin", "", "pkg.py,,\n", false),
		Entry("setuptools hook without direct URL metadata", "", "__editable__.pkg-1.0.pth,,\n", true),
		Entry("recorded legacy link without direct URL metadata", "", "pkg.egg-link,,\n", true),
	)

	It("does not interpret an uncaptured symlinked origin as a normal install", func(ctx SpecContext) {
		image, err := imageOf([]tarEntry{
			regularFile("site/pkg-1.0.dist-info/RECORD", "pkg.py,,\n"),
			regularFile("site/pkg.py", "payload"),
			regularFile("shared/origin", `{"dir_info":{"editable":true}}`),
			symlink("site/pkg-1.0.dist-info/direct_url.json", "/shared/origin"),
		})
		Expect(err).NotTo(HaveOccurred())
		filesets, err := CollectFilesets(ctx, image)
		Expect(err).NotTo(HaveOccurred())
		Expect(filesetOf(filesets, EcosystemPython, "pkg", "1.0").Incomplete).To(BeTrue())
	})

	DescribeTable("preserves uncertainty alongside another copy or origin of the same package",
		func(ctx SpecContext, reverse, previousOccurrences bool) {
			image, err := imageOf([]tarEntry{
				regularFile("site/pkg-1.0.dist-info/RECORD", "__editable__.pkg-1.0.pth,,\n"),
				regularFile("other/pkg-1.0.dist-info/RECORD", "pkg.py,,\n"),
			})
			Expect(err).NotTo(HaveOccurred())
			filesets, err := CollectFilesets(ctx, image)
			Expect(err).NotTo(HaveOccurred())
			bom := cyclonedxutil.NewBOM()
			bom.Components = &[]cdx.Component{{Name: "pkg", Version: "1.0", BOMRef: "pkg:pypi/pkg@1.0", PackageURL: "pkg:pypi/pkg@1.0"}}
			known, err := cyclonedxutil.CloneBOM(bom)
			Expect(err).NotTo(HaveOccurred())
			if previousOccurrences {
				(*known.Components)[0].Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/gone/pkg.py", AdditionalContext: digestOf("gone")}}}
			} else {
				setProperty(&(*known.Components)[0], PropertyFiles, propertyFilesNone)
			}
			RecordOccurrences(bom, filesets.Filesets)
			Expect(incompleteFileEvidence(&(*bom.Components)[0])).To(BeTrue(), "a regular copy cannot make an editable copy's manifest complete")
			if reverse {
				bom, known = known, bom
			}
			merged, err := cyclonedxutil.MergeBOMs(ctx, bom, cyclonedxutil.MergeOpts{BaseBOM: known})
			Expect(err).NotTo(HaveOccurred())
			for range 2 {
				merged, err = cyclonedxutil.CloneBOM(merged)
				Expect(err).NotTo(HaveOccurred())
				RecordOccurrences(merged, []Fileset{{Ecosystem: EcosystemPython, Name: "pkg", Version: "1.0", DeclaresFiles: true}})
				Expect(MarkNotShipped(ctx, merged, &Filesets{Index: emptyIndex()})).To(BeZero())
				Expect(recordedOccurrences(&(*merged.Components)[0])).To(BeNil())
			}
		},
		Entry("unknown before checked-empty", false, false),
		Entry("checked-empty before unknown", true, false),
		Entry("unknown before old occurrences", false, true),
		Entry("old occurrences before unknown", true, true),
	)

	DescribeTable("does not treat editable installation scaffolding as complete payload evidence",
		func(ctx SpecContext, imported []tarEntry) {
			donorImage, err := imageOf([]tarEntry{
				regularFile("site/editable-1.0.dist-info/RECORD", "editable.pth,,\neditable-1.0.dist-info/RECORD,,\neditable-1.0.dist-info/direct_url.json,,\n"),
				regularFile("site/editable-1.0.dist-info/direct_url.json", `{"url":"file:///src/editable","dir_info":{"editable":true}}`),
				regularFile("site/editable.pth", "/src/editable\n"),
				regularFile("src/editable/module.py", "value = 42\n"),
			})
			Expect(err).NotTo(HaveOccurred())
			donorFilesets, err := CollectFilesets(ctx, donorImage)
			Expect(err).NotTo(HaveOccurred())
			bom := &cdx.BOM{SpecVersion: cdx.SpecVersion1_6, Components: &[]cdx.Component{{
				BOMRef: "pkg:pypi/editable@1.0", PackageURL: "pkg:pypi/editable@1.0", Name: "editable", Version: "1.0",
			}}}
			RecordOccurrences(bom, donorFilesets.Filesets)
			Expect(MarkNotShipped(ctx, bom, donorFilesets)).To(BeZero())

			body, err := json.Marshal(bom)
			Expect(err).NotTo(HaveOccurred())
			var inherited cdx.BOM
			Expect(json.Unmarshal(body, &inherited)).To(Succeed())
			image, err := imageOf(imported)
			Expect(err).NotTo(HaveOccurred())
			filesets, err := CollectFilesets(ctx, image)
			Expect(err).NotTo(HaveOccurred())
			RecordOccurrences(&inherited, filesets.Filesets)

			Expect(MarkNotShipped(ctx, &inherited, filesets)).To(BeZero(), "missing editable scaffolding does not prove that the source was omitted")
			Expect(recordedOccurrences(&(*inherited.Components)[0])).To(BeNil(), "neither copied metadata nor a .pth file is complete evidence of editable source files")
		},
		Entry("only source is copied", []tarEntry{regularFile("app/module.py", "value = 42\n")}),
		Entry("only the path hook is copied", []tarEntry{regularFile("site/editable.pth", "/src/editable\n")}),
		Entry("nothing is copied", []tarEntry{regularFile("app/unrelated.txt", "unrelated")}),
	)
})
