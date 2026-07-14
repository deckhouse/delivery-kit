package managedinput

import (
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var _ = Describe("buildResolvers", func() {
	It("returns resolvers in deterministic order across invocations", func() {
		first := buildResolvers()
		firstOrder := make([]config.PackagesDirectiveType, len(first))
		for i, r := range first {
			firstOrder[i] = r.inputType
		}

		for i := 0; i < 20; i++ {
			next := buildResolvers()
			nextOrder := make([]config.PackagesDirectiveType, len(next))
			for j, r := range next {
				nextOrder[j] = r.inputType
			}
			Expect(nextOrder).To(Equal(firstOrder))
		}
	})

	It("orders resolvers by inputType alphabetically", func() {
		built := buildResolvers()
		order := make([]string, len(built))
		for i, r := range built {
			order[i] = string(r.inputType)
		}
		sorted := make([]string, len(order))
		copy(sorted, order)
		sort.Strings(sorted)
		Expect(order).To(Equal(sorted))
	})
})

var _ = Describe("ToCatalogers", func() {
	DescribeTable("maps packages directives to syft catalogers",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("go-mod entries map to the go-module-file-cataloger",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeGoMod,
					FileBased: config.FileBasedSpec{Workdir: "/app/api", Spec: "go.mod", Lock: "go.sum"},
				},
				{
					Type:      config.PackagesDirectiveTypeGoMod,
					FileBased: config.FileBasedSpec{Workdir: "/app/cli", Spec: "go.mod", Lock: "go.sum"},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/api/go.mod", "/app/api/go.sum"}, Workdir: "/app/api"},
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/cli/go.mod", "/app/cli/go.sum"}, Workdir: "/app/cli"},
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

	DescribeTable("filter behavior",
		func(bom *cdx.BOM, catalogers []scanner.Cataloger, expectedNames []string) {
			FilterBOMBySourcePaths(bom, catalogers)
			if bom == nil {
				return
			}
			var names []string
			for _, c := range *bom.Components {
				names = append(names, c.Name)
			}
			Expect(names).To(Equal(expectedNames))
		},

		Entry("keeps only components found by declared catalogers with matching paths",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/api/go.mod")},
					{Name: "github.com/baz/qux", Properties: goModProps("/vendor/tool/go.mod")},
					{Name: "curl", Properties: osProps()},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/api/go.mod", "/app/api/go.sum"}, Workdir: "/app/api"},
			},
			[]string{"github.com/foo/bar"},
		),

		Entry("does nothing when no catalogers are provided",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/api/go.mod")},
				},
			},
			[]scanner.Cataloger(nil),
			[]string{"github.com/foo/bar"},
		),

		Entry("does nothing when BOM is nil",
			(*cdx.BOM)(nil),
			[]scanner.Cataloger{{Name: "x", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/go.mod"}, Workdir: "/app"}},
			[]string(nil),
		),
	)
})

var _ = Describe("ToCatalogers python", func() {
	DescribeTable("maps python directives to python-package-cataloger",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("python-pip maps to python-package-cataloger with spec path only (no lock)",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypePythonPip,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "requirements.txt", Lock: ""},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/requirements.txt"}, Workdir: "/app"},
			},
		),

		Entry("python-uv maps to python-package-cataloger with spec and lock paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypePythonUV,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Lock: "uv.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/pyproject.toml", "/app/uv.lock"}, Workdir: "/app"},
			},
		),

		Entry("python-poetry maps to python-package-cataloger with spec and lock paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypePythonPoetry,
					FileBased: config.FileBasedSpec{Workdir: "/svc", Spec: "pyproject.toml", Lock: "poetry.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/svc/pyproject.toml", "/svc/poetry.lock"}, Workdir: "/svc"},
			},
		),
	)
})

var _ = Describe("FilterBOMBySourcePaths python declared", func() {
	pythonProps := func(specPath string) *[]cdx.Property {
		return &[]cdx.Property{
			{Name: "syft:package:foundBy", Value: "python-package-cataloger"},
			{Name: "syft:location:0:path", Value: specPath},
		}
	}

	goModProps := func(path string) *[]cdx.Property {
		return &[]cdx.Property{
			{Name: "syft:package:foundBy", Value: "go-module-file-cataloger"},
			{Name: "syft:location:0:path", Value: path},
		}
	}

	DescribeTable("exact-match filtering for python declared and go-mod",
		func(bom *cdx.BOM, catalogers []scanner.Cataloger, expectedNames []string) {
			FilterBOMBySourcePaths(bom, catalogers)
			Expect(*bom.Components).To(HaveLen(len(expectedNames)))
			for i, name := range expectedNames {
				Expect((*bom.Components)[i].Name).To(Equal(name))
			}
		},

		Entry("python-uv: keeps component with matching pyproject.toml path",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "requests", Properties: pythonProps("/app/pyproject.toml")},
					{Name: "flask", Properties: pythonProps("/other/pyproject.toml")},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/pyproject.toml", "/app/uv.lock"}, Workdir: "/app"},
			},
			[]string{"requests"},
		),

		Entry("python-pip: keeps component with matching requirements.txt path",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "requests", Properties: pythonProps("/app/requirements.txt")},
					{Name: "flask", Properties: pythonProps("/other/requirements.txt")},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/requirements.txt"}, Workdir: "/app"},
			},
			[]string{"requests"},
		),

		Entry("python-poetry: keeps component with matching lock path",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "requests", Properties: pythonProps("/svc/poetry.lock")},
					{Name: "flask", Properties: pythonProps("/app/poetry.lock")},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/svc/pyproject.toml", "/svc/poetry.lock"}, Workdir: "/svc"},
			},
			[]string{"requests"},
		),

		Entry("regression: go-mod exact-match still works alongside python cataloger",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/go.mod")},
					{Name: "github.com/baz/qux", Properties: goModProps("/other/go.mod")},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/go.mod", "/app/go.sum"}, Workdir: "/app"},
			},
			[]string{"github.com/foo/bar"},
		),
	)
})
