package managedinput

import (
	"fmt"
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

var _ = Describe("ToCatalogers rust", func() {
	DescribeTable("maps rust-cargo directive to rust-cargo-lock-cataloger",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("rust-cargo maps to rust-cargo-lock-cataloger with spec and lock paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeRustCargo,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml", Lock: "Cargo.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/Cargo.toml", "/app/Cargo.lock"}, Workdir: "/app"},
			},
		),

		Entry("rust-cargo with nested workdir includes correct paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeRustCargo,
					FileBased: config.FileBasedSpec{Workdir: "/src/service", Spec: "Cargo.toml", Lock: "Cargo.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/src/service/Cargo.toml", "/src/service/Cargo.lock"}, Workdir: "/src/service"},
			},
		),

		Entry("multiple rust-cargo entries produce multiple catalogers",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeRustCargo,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml", Lock: "Cargo.lock"},
				},
				{
					Type:      config.PackagesDirectiveTypeRustCargo,
					FileBased: config.FileBasedSpec{Workdir: "/lib", Spec: "Cargo.toml", Lock: "Cargo.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/Cargo.toml", "/app/Cargo.lock"}, Workdir: "/app"},
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/lib/Cargo.toml", "/lib/Cargo.lock"}, Workdir: "/lib"},
			},
		),
	)
})

var _ = Describe("ToCatalogers javascript", func() {
	DescribeTable("maps javascript directives to javascript-lock-cataloger",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("javascript-npm maps to javascript-lock-cataloger with spec and lock paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeJavaScriptNpm,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "package.json", Lock: "package-lock.json"},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/package-lock.json"}, Workdir: "/app"},
			},
		),

		Entry("javascript-yarn maps to javascript-lock-cataloger with spec and yarn.lock paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeJavaScriptYarn,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "package.json", Lock: "yarn.lock"},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/yarn.lock"}, Workdir: "/app"},
			},
		),

		Entry("javascript-pnpm maps to javascript-lock-cataloger with spec and pnpm-lock.yaml paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeJavaScriptPnpm,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "package.json", Lock: "pnpm-lock.yaml"},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/pnpm-lock.yaml"}, Workdir: "/app"},
			},
		),

		Entry("javascript-npm with nested workdir includes correct paths",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeJavaScriptNpm,
					FileBased: config.FileBasedSpec{Workdir: "/src/web", Spec: "package.json", Lock: "package-lock.json"},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/src/web/package.json", "/src/web/package-lock.json"}, Workdir: "/src/web"},
			},
		),

		Entry("multiple javascript entries produce multiple catalogers",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeJavaScriptNpm,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "package.json", Lock: "package-lock.json"},
				},
				{
					Type:      config.PackagesDirectiveTypeJavaScriptPnpm,
					FileBased: config.FileBasedSpec{Workdir: "/sdk", Spec: "package.json", Lock: "pnpm-lock.yaml"},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/package-lock.json"}, Workdir: "/app"},
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/sdk/package.json", "/sdk/pnpm-lock.yaml"}, Workdir: "/sdk"},
			},
		),
	)
})

var _ = Describe("ToCatalogers lua", func() {
	DescribeTable("maps lua-rock directive to lua-rock-cataloger",
		func(packages []*config.PackagesDirective, expected []scanner.Cataloger) {
			Expect(ToCatalogers(packages)).To(Equal(expected))
		},

		Entry("lua-rock maps to lua-rock-cataloger with spec path only (no lock)",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeLuaRock,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "app-0.1-1.rockspec", Lock: ""},
				},
			},
			[]scanner.Cataloger{
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/app-0.1-1.rockspec"}, Workdir: "/app"},
			},
		),

		Entry("lua-rock with nested spec path includes correct path",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeLuaRock,
					FileBased: config.FileBasedSpec{Workdir: "/src", Spec: "rockspecs/app-0.1-1.rockspec", Lock: ""},
				},
			},
			[]scanner.Cataloger{
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/src/rockspecs/app-0.1-1.rockspec"}, Workdir: "/src"},
			},
		),

		Entry("multiple lua-rock entries produce multiple catalogers",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeLuaRock,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "app-0.1-1.rockspec", Lock: ""},
				},
				{
					Type:      config.PackagesDirectiveTypeLuaRock,
					FileBased: config.FileBasedSpec{Workdir: "/lib", Spec: "lib-2.0-1.rockspec", Lock: ""},
				},
			},
			[]scanner.Cataloger{
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/app-0.1-1.rockspec"}, Workdir: "/app"},
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/lib/lib-2.0-1.rockspec"}, Workdir: "/lib"},
			},
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

var _ = Describe("FilterBOMBySourcePaths rust-cargo declared", func() {
	cargoProps := func(paths ...string) *[]cdx.Property {
		props := []cdx.Property{
			{Name: "syft:package:foundBy", Value: "rust-cargo-lock-cataloger"},
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

	DescribeTable("exact-match path filtering for rust-cargo",
		func(bom *cdx.BOM, catalogers []scanner.Cataloger, expectedNames []string) {
			FilterBOMBySourcePaths(bom, catalogers)
			Expect(*bom.Components).To(HaveLen(len(expectedNames)))
			for i, name := range expectedNames {
				Expect((*bom.Components)[i].Name).To(Equal(name))
			}
		},

		Entry("rust component matching Cargo.toml path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "anyhow", Properties: cargoProps("/app/Cargo.toml")},
					{Name: "serde", Properties: cargoProps("/other/Cargo.toml")},
				},
			},
			[]scanner.Cataloger{
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/Cargo.toml", "/app/Cargo.lock"}, Workdir: "/app"},
			},
			[]string{"anyhow"},
		),

		Entry("rust component matching Cargo.lock path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "anyhow", Properties: cargoProps("/app/Cargo.lock")},
					{Name: "serde", Properties: cargoProps("/other/Cargo.lock")},
				},
			},
			[]scanner.Cataloger{
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/Cargo.toml", "/app/Cargo.lock"}, Workdir: "/app"},
			},
			[]string{"anyhow"},
		),

		Entry("rust component from different workdir is filtered out",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "anyhow", Properties: cargoProps("/app/Cargo.toml")},
					{Name: "anyhow", Properties: cargoProps("/lib/Cargo.toml")},
				},
			},
			[]scanner.Cataloger{
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/Cargo.toml", "/app/Cargo.lock"}, Workdir: "/app"},
			},
			[]string{"anyhow"},
		),

		Entry("regression: go-mod exact-match still works alongside rust-cargo cataloger",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/go.mod")},
					{Name: "anyhow", Properties: cargoProps("/crate/Cargo.toml")},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/go.mod", "/app/go.sum"}, Workdir: "/app"},
				{Name: "rust-cargo-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/crate/Cargo.toml", "/crate/Cargo.lock"}, Workdir: "/crate"},
			},
			[]string{"github.com/foo/bar", "anyhow"},
		),
	)
})

var _ = Describe("FilterBOMBySourcePaths javascript declared", func() {
	javascriptProps := func(paths ...string) *[]cdx.Property {
		props := []cdx.Property{
			{Name: "syft:package:foundBy", Value: "javascript-lock-cataloger"},
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

	DescribeTable("exact-match path filtering for javascript",
		func(bom *cdx.BOM, catalogers []scanner.Cataloger, expectedNames []string) {
			FilterBOMBySourcePaths(bom, catalogers)
			Expect(*bom.Components).To(HaveLen(len(expectedNames)))
			for i, name := range expectedNames {
				Expect((*bom.Components)[i].Name).To(Equal(name))
			}
		},

		Entry("javascript-npm component matching package.json path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Properties: javascriptProps("/app/package.json")},
					{Name: "express", Properties: javascriptProps("/other/package.json")},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/package-lock.json"}, Workdir: "/app"},
			},
			[]string{"lodash"},
		),

		Entry("javascript-yarn component matching yarn.lock path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Properties: javascriptProps("/app/yarn.lock")},
					{Name: "express", Properties: javascriptProps("/other/yarn.lock")},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/yarn.lock"}, Workdir: "/app"},
			},
			[]string{"lodash"},
		),

		Entry("javascript-pnpm component matching pnpm-lock.yaml path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Properties: javascriptProps("/app/pnpm-lock.yaml")},
					{Name: "express", Properties: javascriptProps("/other/pnpm-lock.yaml")},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/pnpm-lock.yaml"}, Workdir: "/app"},
			},
			[]string{"lodash"},
		),

		Entry("javascript component from different workdir is filtered out",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Properties: javascriptProps("/app/package.json")},
					{Name: "lodash", Properties: javascriptProps("/lib/package.json")},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/package-lock.json"}, Workdir: "/app"},
			},
			[]string{"lodash"},
		),

		Entry("regression: go-mod exact-match still works alongside javascript cataloger",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/go.mod")},
					{Name: "lodash", Properties: javascriptProps("/app/package.json")},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/go.mod", "/app/go.sum"}, Workdir: "/app"},
				{Name: "javascript-lock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/package.json", "/app/package-lock.json"}, Workdir: "/app"},
			},
			[]string{"github.com/foo/bar", "lodash"},
		),
	)
})

var _ = Describe("FilterBOMBySourcePaths lua-rock declared", func() {
	luaProps := func(paths ...string) *[]cdx.Property {
		props := []cdx.Property{
			{Name: "syft:package:foundBy", Value: "lua-rock-cataloger"},
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

	DescribeTable("exact-match path filtering for lua-rock",
		func(bom *cdx.BOM, catalogers []scanner.Cataloger, expectedNames []string) {
			FilterBOMBySourcePaths(bom, catalogers)
			Expect(*bom.Components).To(HaveLen(len(expectedNames)))
			for i, name := range expectedNames {
				Expect((*bom.Components)[i].Name).To(Equal(name))
			}
		},

		Entry("lua component matching rockspec path is kept",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "app", Properties: luaProps("/app/app-0.1-1.rockspec")},
					{Name: "other", Properties: luaProps("/other/other-0.1-1.rockspec")},
				},
			},
			[]scanner.Cataloger{
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/app-0.1-1.rockspec"}, Workdir: "/app"},
			},
			[]string{"app"},
		),

		Entry("lua component from different workdir is filtered out",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "app", Properties: luaProps("/app/app-0.1-1.rockspec")},
					{Name: "app", Properties: luaProps("/lib/app-0.1-1.rockspec")},
				},
			},
			[]scanner.Cataloger{
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/app-0.1-1.rockspec"}, Workdir: "/app"},
			},
			[]string{"app"},
		),

		Entry("regression: go-mod exact-match still works alongside lua-rock cataloger",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "github.com/foo/bar", Properties: goModProps("/app/go.mod")},
					{Name: "app", Properties: luaProps("/rock/app-0.1-1.rockspec")},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/app/go.mod", "/app/go.sum"}, Workdir: "/app"},
				{Name: "lua-rock-cataloger", FilterMode: scanner.CatalogerFilterExactPath, SourcePaths: []string{"/rock/app-0.1-1.rockspec"}, Workdir: "/rock"},
			},
			[]string{"github.com/foo/bar", "app"},
		),
	)
})
