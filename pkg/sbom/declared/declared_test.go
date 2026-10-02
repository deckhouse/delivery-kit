package declared

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/config"
)

var _ = Describe("ParseSpec", func() {
	DescribeTable("declares the packages a spec file names",
		func(ecosystem config.PackagesDirectiveType, spec string, expected []Package) {
			pkgs, err := ParseSpec(ecosystem, []byte(spec))
			Expect(err).NotTo(HaveOccurred())
			Expect(pkgs).To(Equal(expected))
		},
		Entry("go.mod: direct requires only, replaces applied",
			config.PackagesDirectiveTypeGoMod,
			`module example.com/app

go 1.22

require (
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.8.0
	golang.org/x/sys v0.1.0 // indirect
	example.com/mylib v0.0.0
	github.com/old/pinned v1.0.0
	github.com/old/unpinned v1.0.0
)

replace example.com/mylib => ./mylib

replace github.com/spf13/cobra => github.com/werf/3p-cobra v1.8.1-werf

replace github.com/old/pinned v1.0.0 => github.com/new/pinned v2.0.0

replace github.com/old/unpinned v0.9.0 => github.com/new/unpinned v2.0.0
`,
			[]Package{
				{Name: "github.com/pkg/errors", Version: "v0.9.1"},
				{Name: "github.com/werf/3p-cobra", Version: "v1.8.1-werf"},
				{Name: "example.com/mylib"},
				{Name: "github.com/new/pinned", Version: "v2.0.0"},
				{Name: "github.com/old/unpinned", Version: "v1.0.0"},
			}),
		Entry("package.json: dependencies and devDependencies, no versions",
			config.PackagesDirectiveTypeJavaScriptNpm,
			`{"name":"app","dependencies":{"lodash":"^4.17.21","@scope/pkg":"1.0.0"},"devDependencies":{"jest":"29"}}`,
			[]Package{{Name: "@scope/pkg"}, {Name: "jest"}, {Name: "lodash"}}),
		Entry("Cargo.toml: [dependencies] with renamed crates, no versions",
			config.PackagesDirectiveTypeRustCargo,
			`[package]
name = "app"
version = "0.1.0"

[dependencies]
anyhow = "1.0.86"
serde = { version = "1", features = ["derive"] }
my_tokio = { package = "tokio", version = "1" }

[dev-dependencies]
criterion = "0.5"
`,
			[]Package{{Name: "anyhow"}, {Name: "serde"}, {Name: "tokio"}}),
		Entry("pyproject.toml: PEP 621 dependencies keep an exact pin",
			config.PackagesDirectiveTypePythonUV,
			`[project]
name = "app"
dependencies = [
  "requests==2.32.3",
  "Flask>=3.0",
  "uvicorn[standard]==0.30.0 ; python_version >= '3.8'",
  "pydantic (>=2,<3)",
  "mylib @ git+https://example.com/mylib.git",
]
`,
			[]Package{
				{Name: "requests", Version: "2.32.3"},
				{Name: "Flask"},
				{Name: "uvicorn", Version: "0.30.0"},
				{Name: "pydantic"},
			}),
		Entry("pyproject.toml: poetry dependencies skip python, no versions",
			config.PackagesDirectiveTypePythonPoetry,
			`[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.32.3"
httpx = { version = "^0.27", extras = ["http2"] }
`,
			[]Package{{Name: "httpx"}, {Name: "requests"}}),
		Entry("requirements.txt: pins kept, options and comments skipped",
			config.PackagesDirectiveTypePythonPip,
			`# deps
-r base.txt
--index-url https://pypi.example.com/simple
requests==2.32.3  # http
Django>=4.2,<5
pyyaml == 6.0.*
-e git+https://example.com/repo.git#egg=repo
./local/path
`,
			[]Package{{Name: "requests", Version: "2.32.3"}, {Name: "Django"}, {Name: "pyyaml"}}),
		Entry("rockspec: the rock itself",
			config.PackagesDirectiveTypeLuaRock,
			`package = "werf-sbom-lua-app"
version = "0.1-1"
dependencies = {
   "lua >= 5.1"
}
`,
			[]Package{{Name: "werf-sbom-lua-app", Version: "0.1-1"}}),
	)

	It("rejects an ecosystem without a spec file", func() {
		_, err := ParseSpec(config.PackagesDirectiveTypeOSPM, nil)
		Expect(err).To(MatchError(ContainSubstring("has no spec file")))
	})

	It("reports a malformed go.mod", func() {
		_, err := ParseSpec(config.PackagesDirectiveTypeGoMod, []byte("require ("))
		Expect(err).To(MatchError(ContainSubstring("parse go.mod")))
	})
})

var _ = Describe("FromOSPMSpec", func() {
	It("splits name==version entries", func() {
		Expect(FromOSPMSpec([]string{"jq==1.8.1", "curl", " ", "openssl==3.6.2"})).To(Equal([]Package{
			{Name: "jq", Version: "1.8.1"},
			{Name: "curl"},
			{Name: "openssl", Version: "3.6.2"},
		}))
	})
})

var _ = Describe("MatchComponents", func() {
	component := func(ref, purl string) cdx.Component {
		return cdx.Component{BOMRef: ref, PackageURL: purl}
	}

	DescribeTable("finds the components a declaration names",
		func(ecosystem config.PackagesDirectiveType, components []cdx.Component, pkgs []Package, expected []string) {
			bom := &cdx.BOM{Components: &components}
			Expect(MatchComponents(context.Background(), bom, ecosystem, pkgs)).To(Equal(expected))
		},
		Entry("go module by path and exact version",
			config.PackagesDirectiveTypeGoMod,
			[]cdx.Component{
				component("errors", "pkg:golang/github.com/pkg/errors@v0.9.1?package-id=1"),
				component("sys", "pkg:golang/golang.org/x/sys@v0.1.0?package-id=2"),
			},
			[]Package{{Name: "github.com/pkg/errors", Version: "v0.9.1"}},
			[]string{"errors"}),
		Entry("go module with a mismatching version does not match",
			config.PackagesDirectiveTypeGoMod,
			[]cdx.Component{component("errors", "pkg:golang/github.com/pkg/errors@v0.9.1")},
			[]Package{{Name: "github.com/pkg/errors", Version: "v0.8.0"}},
			nil),
		Entry("go module paths are case-insensitive",
			config.PackagesDirectiveTypeGoMod,
			[]cdx.Component{component("bb", "pkg:golang/github.com/burntsushi/toml@v1.6.0")},
			[]Package{{Name: "github.com/BurntSushi/toml", Version: "v1.6.0"}},
			[]string{"bb"}),
		Entry("a declaration without a version matches every version",
			config.PackagesDirectiveTypeRustCargo,
			[]cdx.Component{
				component("a1", "pkg:cargo/anyhow@1.0.86"),
				component("a2", "pkg:cargo/anyhow@1.0.90"),
				component("s", "pkg:cargo/serde@1.0.0"),
			},
			[]Package{{Name: "anyhow"}},
			[]string{"a1", "a2"}),
		Entry("scoped npm package",
			config.PackagesDirectiveTypeJavaScriptNpm,
			[]cdx.Component{
				component("core", "pkg:npm/%40actions/core@1.6.0"),
				component("lodash", "pkg:npm/lodash@4.17.21"),
			},
			[]Package{{Name: "@actions/core"}},
			[]string{"core"}),
		Entry("PyPI names fold case and separators",
			config.PackagesDirectiveTypePythonPip,
			[]cdx.Component{component("yaml", "pkg:pypi/pyyaml@6.0.1"), component("fl", "pkg:pypi/flask-cors@4.0.0")},
			[]Package{{Name: "PyYAML"}, {Name: "Flask_Cors"}},
			[]string{"yaml", "fl"}),
		Entry("os-pm generic package by name and version",
			config.PackagesDirectiveTypeOSPM,
			[]cdx.Component{
				component("jq", "pkg:generic/jq@1.8.1?containerfactoryversion=v1"),
				component("curl", "pkg:generic/curl@8.12.1?containerfactoryversion=v1"),
			},
			[]Package{{Name: "jq", Version: "1.8.1"}, {Name: "curl", Version: "8.0.0"}},
			[]string{"jq"}),
		Entry("a component of another type is never matched",
			config.PackagesDirectiveTypeGoMod,
			[]cdx.Component{component("x", "pkg:npm/github.com/pkg/errors@v0.9.1")},
			[]Package{{Name: "github.com/pkg/errors", Version: "v0.9.1"}},
			nil),
		Entry("a component without a bom-ref or purl is skipped",
			config.PackagesDirectiveTypeGoMod,
			[]cdx.Component{{PackageURL: "pkg:golang/github.com/pkg/errors@v0.9.1"}, {BOMRef: "no-purl", Name: "github.com/pkg/errors"}},
			[]Package{{Name: "github.com/pkg/errors", Version: "v0.9.1"}},
			nil),
	)

	It("walks components nested under the metadata component and other components", func() {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{Component: &cdx.Component{
				BOMRef:     "image",
				Components: &[]cdx.Component{component("under-root", "pkg:cargo/anyhow@1.0.86")},
			}},
			Components: &[]cdx.Component{{
				BOMRef:     "parent",
				Components: &[]cdx.Component{component("nested", "pkg:cargo/serde@1.0.0")},
			}},
		}
		Expect(MatchComponents(context.Background(), bom, config.PackagesDirectiveTypeRustCargo, []Package{{Name: "anyhow"}, {Name: "serde"}})).
			To(Equal([]string{"under-root", "nested"}))
	})
})

var _ = Describe("AddRootEdge", func() {
	It("creates the edge sourced at the metadata component", func() {
		bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{BOMRef: "image"}}}
		AddRootEdge(bom, []string{"a", "b", "a"})
		Expect(lo.FromPtr(bom.Dependencies)).To(Equal([]cdx.Dependency{{Ref: "image", Dependencies: &[]string{"a", "b"}}}))
	})

	It("extends an existing edge sourced at the metadata component", func() {
		bom := &cdx.BOM{
			Metadata:     &cdx.Metadata{Component: &cdx.Component{BOMRef: "image"}},
			Dependencies: &[]cdx.Dependency{{Ref: "a", Dependencies: &[]string{"b"}}, {Ref: "image", Dependencies: &[]string{"a"}}},
		}
		AddRootEdge(bom, []string{"c", "a"})
		Expect(lo.FromPtr(bom.Dependencies)).To(Equal([]cdx.Dependency{
			{Ref: "a", Dependencies: &[]string{"b"}},
			{Ref: "image", Dependencies: &[]string{"a", "c"}},
		}))
	})

	It("does nothing without a root ref or without refs", func() {
		bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{}}}
		AddRootEdge(bom, []string{"a"})
		Expect(bom.Dependencies).To(BeNil())

		bom = &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{BOMRef: "image"}}}
		AddRootEdge(bom, nil)
		Expect(bom.Dependencies).To(BeNil())
	})
})
