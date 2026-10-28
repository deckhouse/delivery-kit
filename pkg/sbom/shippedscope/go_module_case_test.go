package shippedscope

import (
	"bytes"
	"runtime/debug"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("Case-sensitive Go module evidence", func() {
	ginkgo.DescribeTable("preserves the module identity encoded in a PURL", func(purl, expectedName, expectedVersion string) {
		component := componentOf(purl)
		component.Name = "unrelated display name"
		key, ok := keyOfComponent(&component)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(key).To(gomega.Equal(componentKey{ecosystem: EcosystemGo, name: expectedName, version: expectedVersion}))
		gomega.Expect(component.PackageURL).To(gomega.Equal(purl))
	},
		ginkgo.Entry("uppercase namespace", "pkg:golang/github.com/Masterminds/semver/v3@v3.5.0", "github.com/Masterminds/semver/v3", "v3.5.0"),
		ginkgo.Entry("uppercase terminal segment", "pkg:golang/example.test/Owner/Library@v1.2.3", "example.test/Owner/Library", "v1.2.3"),
		ginkgo.Entry("percent-encoded namespace and name", "pkg:golang/example.test/%4Fwner/%4Cibrary@v1.2.3", "example.test/Owner/Library", "v1.2.3"),
		ginkgo.Entry("qualifiers and subpath", "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.21.1?goarch=amd64&goos=linux#internal", "github.com/Azure/azure-sdk-for-go/sdk/azcore", "v1.21.1"),
		ginkgo.Entry("case-insensitive type and leading slashes", "pkg:///GoLang/example.test/Owner/Library@v1.2.3-RC.1", "example.test/Owner/Library", "v1.2.3-RC.1"),
		ginkgo.Entry("versionless module", "pkg:golang/example.test/Owner/Library", "example.test/Owner/Library", ""),
		ginkgo.Entry("encoded version", "pkg:golang/example.test/Owner/Library@v1.2.3%2Bincompatible", "example.test/Owner/Library", "v1.2.3+incompatible"),
		ginkgo.Entry("lowercase module", "pkg:golang/example.test/owner/library@v1.2.3", "example.test/owner/library", "v1.2.3"),
	)

	ginkgo.It("rejects malformed Go PURLs without inventing a display-name identity", func() {
		for _, purl := range []string{"pkg:golang/example.test/%ZZ@v1.0.0", "pkg:golang/", "golang:example.test/Owner@v1.0.0"} {
			component := componentOf(purl)
			component.Name = "example.test/Owner"
			_, ok := keyOfComponent(&component)
			gomega.Expect(ok).To(gomega.BeFalse(), purl)
		}
	})

	ginkgo.It("retains a real mixed-case module through relocation and SBOM round trips without retaining its lowercase namesake", func(ctx ginkgo.SpecContext) {
		binary := caseSensitiveGoBinary(ctx)
		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(classification.Go).To(gomega.Equal(VerdictNames))
		gomega.Expect(classification.Modules).To(gomega.ContainElement("example.test/Owner/Library"))
		gomega.Expect(classification.Modules).NotTo(gomega.ContainElement("example.test/owner/library"))

		upperPURL := "pkg:golang/example.test/Owner/Library@v1.0.0"
		lowerPURL := "pkg:golang/example.test/owner/library@v1.0.0"
		upper := componentOf(upperPURL)
		upper.Name = "library"
		lower := componentOf(lowerPURL)
		lower.Name = "example.test/Owner/Library"
		donor := cyclonedxutil.NewBOM()
		donor.Components = &[]cdx.Component{upper, lower}
		digest := digestOf(string(binary))
		produced := &ProducedFiles{Known: true, Files: []ProducedFile{{Path: "/build/app", Digest: digest, Classification: classification}}}
		PrepareBinaryOccurrences(ctx, donor, produced)
		gomega.Expect(binaryOccurrences(&(*donor.Components)[0])).To(gomega.Equal([]binaryOccurrence{{Path: "/build/app", Digest: digest}}))
		gomega.Expect(binaryOccurrences(&(*donor.Components)[1])).To(gomega.BeEmpty())

		for _, path := range []string{"/usr/bin/renamed", "/another/app"} {
			data, err := cyclonedxutil.ToJSON(donor)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			NormalizeInheritedBinaryOccurrences(ctx, read)
			donor, err = cyclonedxutil.MergeBOMs(ctx, cyclonedxutil.NewBOM(), cyclonedxutil.MergeOpts{BaseBOM: read})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			RecordProducedBinaryOccurrences(ctx, donor, &ProducedFiles{Known: true})
			gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(indexOf(map[string]File{path: {Digest: digest, Size: int64(len(binary))}})))).To(gomega.Equal(1))
			for _, component := range lo.FromPtr(donor.Components) {
				switch component.PackageURL {
				case upperPURL:
					gomega.Expect(propertyValue(&component, PropertyShipped)).To(gomega.BeEmpty())
					gomega.Expect(binaryOccurrences(&component)).To(gomega.ContainElement(binaryOccurrence{Path: "/build/app", Digest: digest}))
				case lowerPURL:
					gomega.Expect(propertyValue(&component, PropertyShipped)).To(gomega.Equal("false"))
				default:
					ginkgo.Fail("unexpected component " + component.PackageURL)
				}
			}
		}
		gomega.Expect(MarkNotShipped(ctx, donor, filesetsOf(emptyIndex()))).To(gomega.Equal(2))
	})

	ginkgo.It("matches both original and replacement module paths without folding either", func(ctx ginkgo.SpecContext) {
		verdict, modules := goEvidence(&debug.BuildInfo{GoVersion: "go1.27.0", Path: "example.test/app", Deps: []*debug.Module{{
			Path: "example.test/Original/Library", Version: "v1.0.0", Replace: &debug.Module{Path: "example.test/Fork/Library", Version: "v1.1.0"},
		}}})
		gomega.Expect(verdict).To(gomega.Equal(VerdictNames))
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{
			componentOf("pkg:golang/example.test/Original/Library@v1.0.0"),
			componentOf("pkg:golang/example.test/Fork/Library@v1.1.0"),
			componentOf("pkg:golang/example.test/original/library@v1.0.0"),
			componentOf("pkg:golang/example.test/fork/library@v1.1.0"),
		}
		produced := &ProducedFiles{Known: true, Files: []ProducedFile{{Path: "/app", Digest: digestOf("replaced"), Classification: BinaryClassification{Go: verdict, Modules: modules, Rust: VerdictNone}}}}
		PrepareBinaryOccurrences(ctx, bom, produced)
		gomega.Expect(MarkNotShipped(ctx, bom, filesetsOf(indexOf(map[string]File{"/app": {Digest: digestOf("replaced"), Size: 8}})))).To(gomega.Equal(2))
		for i, component := range *bom.Components {
			if i < 2 {
				gomega.Expect(propertyValue(&component, PropertyShipped)).To(gomega.BeEmpty())
			} else {
				gomega.Expect(propertyValue(&component, PropertyShipped)).To(gomega.Equal("false"))
			}
		}
	})
})
