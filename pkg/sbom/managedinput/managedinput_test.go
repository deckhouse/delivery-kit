package managedinput

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var _ = Describe("ToCatalogers", func() {
	DescribeTable("maps packages directives to syft catalogers",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("go-mod entries map to the go-module-file-cataloger",
			[]*config.PackagesDirective{
				{
					Type:  config.PackagesDirectiveTypeGoMod,
					GoMod: config.GoModSpec{Workdir: "/app/api", Spec: "go.mod", Lock: "go.sum"},
				},
				{
					Type:  config.PackagesDirectiveTypeGoMod,
					GoMod: config.GoModSpec{Workdir: "/app/cli", Spec: "go.mod", Lock: "go.sum"},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", SourcePaths: []string{"/app/api/go.mod", "/app/api/go.sum"}},
				{Name: "go-module-file-cataloger", SourcePaths: []string{"/app/cli/go.mod", "/app/cli/go.sum"}},
			},
		),

		Entry("os-pm entries are skipped",
			[]*config.PackagesDirective{
				{
					Type: config.PackagesDirectiveTypeOSPM,
					Spec: config.PackagesSpec{Packages: []string{"curl"}},
				},
			},
			[]scanner.Cataloger(nil),
		),

		Entry("nil packages yield no catalogers",
			[]*config.PackagesDirective(nil),
			[]scanner.Cataloger(nil),
		),
	)
})

var _ = Describe("FilterBOMBySourcePaths", func() {
	goModProps := func(path string) *[]cdx.Property {
		return &[]cdx.Property{
			{Name: "syft:package:foundBy", Value: "go-module-file-cataloger"},
			{Name: "syft:location:0:path", Value: path},
		}
	}

	osProps := func() *[]cdx.Property {
		return &[]cdx.Property{
			{Name: "syft:package:foundBy", Value: "dpkg-db-cataloger"},
			{Name: "syft:location:0:path", Value: "/var/lib/dpkg/status"},
		}
	}

	It("keeps only components found by declared catalogers with matching paths", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "github.com/foo/bar", Properties: goModProps("/app/api/go.mod")},
				{Name: "github.com/baz/qux", Properties: goModProps("/vendor/tool/go.mod")},
				{Name: "curl", Properties: osProps()},
			},
		}

		catalogers := []scanner.Cataloger{
			{Name: "go-module-file-cataloger", SourcePaths: []string{"/app/api/go.mod", "/app/api/go.sum"}},
		}

		FilterBOMBySourcePaths(bom, catalogers)

		Expect(*bom.Components).To(HaveLen(1))
		Expect((*bom.Components)[0].Name).To(Equal("github.com/foo/bar"))
	})

	It("does nothing when no catalogers are provided", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "github.com/foo/bar", Properties: goModProps("/app/api/go.mod")},
			},
		}

		FilterBOMBySourcePaths(bom, nil)

		Expect(*bom.Components).To(HaveLen(1))
	})

	It("does nothing when BOM is nil", func() {
		FilterBOMBySourcePaths(nil, []scanner.Cataloger{{Name: "x", SourcePaths: []string{"/app/go.mod"}}})
	})
})
