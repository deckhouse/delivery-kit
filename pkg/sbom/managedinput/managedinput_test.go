package managedinput

import (
	"fmt"

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

var _ = Describe("ToCatalogers python", func() {
	DescribeTable("maps python directives to python-package-cataloger",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("python-pip maps to python-package-cataloger with spec path only (no lock)",
			[]*config.PackagesDirective{
				{
					Type:   config.PackagesDirectiveTypePythonPip,
					Python: config.PythonSpec{Manager: config.PackagesDirectiveTypePythonPip, Workdir: "/app", Spec: "requirements.txt", Lock: ""},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", SourcePaths: []string{"/app/requirements.txt"}},
			},
		),

		Entry("python-uv maps to python-package-cataloger with spec and lock paths",
			[]*config.PackagesDirective{
				{
					Type:   config.PackagesDirectiveTypePythonUV,
					Python: config.PythonSpec{Manager: config.PackagesDirectiveTypePythonUV, Workdir: "/app", Spec: "pyproject.toml", Lock: "uv.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", SourcePaths: []string{"/app/pyproject.toml", "/app/uv.lock"}},
			},
		),

		Entry("python-poetry maps to python-package-cataloger with spec and lock paths",
			[]*config.PackagesDirective{
				{
					Type:   config.PackagesDirectiveTypePythonPoetry,
					Python: config.PythonSpec{Manager: config.PackagesDirectiveTypePythonPoetry, Workdir: "/svc", Spec: "pyproject.toml", Lock: "poetry.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", SourcePaths: []string{"/svc/pyproject.toml", "/svc/poetry.lock"}},
			},
		),
	)
})

var _ = Describe("FilterBOMBySourcePaths python declared", func() {
	pythonProps := func(paths ...string) *[]cdx.Property {
		props := []cdx.Property{
			{Name: "syft:package:foundBy", Value: "python-package-cataloger"},
		}
		for i, p := range paths {
			props = append(props, cdx.Property{
				Name:  fmt.Sprintf("syft:location:%d:path", i),
				Value: p,
			})
		}
		return &props
	}

	goModProps := func(path string) *[]cdx.Property {
		return &[]cdx.Property{
			{Name: "syft:package:foundBy", Value: "go-module-file-cataloger"},
			{Name: "syft:location:0:path", Value: path},
		}
	}

	DescribeTable("exact-match path filtering for python and go-mod",
		func(bom *cdx.BOM, catalogers []scanner.Cataloger, expectedNames []string) {
			FilterBOMBySourcePaths(bom, catalogers)
			Expect(*bom.Components).To(HaveLen(len(expectedNames)))
			for i, name := range expectedNames {
				Expect((*bom.Components)[i].Name).To(Equal(name))
			}
		},

		Entry("python pip component with matching requirements.txt path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "requests", Properties: pythonProps("/app/requirements.txt")},
					{Name: "flask", Properties: pythonProps("/other/requirements.txt")},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", SourcePaths: []string{"/app/requirements.txt"}},
			},
			[]string{"requests"},
		),

		Entry("python uv component is kept when both spec and lock paths match",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "requests", Properties: pythonProps("/svc/pyproject.toml")},
					{Name: "requests", Properties: pythonProps("/svc/uv.lock")},
					{Name: "flask", Properties: pythonProps("/other/pyproject.toml")},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", SourcePaths: []string{"/svc/pyproject.toml", "/svc/uv.lock"}},
			},
			[]string{"requests", "requests"},
		),

		Entry("regression: go-mod exact-match still works alongside python cataloger",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/go.mod")},
					{Name: "github.com/baz/qux", Properties: goModProps("/other/go.mod")},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", SourcePaths: []string{"/app/go.mod", "/app/go.sum"}},
			},
			[]string{"github.com/foo/bar"},
		),
	)
})
