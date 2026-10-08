package managedinput

import (
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
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
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app/api", SourcePaths: []string{"/app/api/go.mod"}, OptionalSourcePaths: []string{"/app/api/go.sum"}, SourceLang: "Go", Enrichment: goModCacheEnrichment("/app/api/go.sum")},
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app/cli", SourcePaths: []string{"/app/cli/go.mod"}, OptionalSourcePaths: []string{"/app/cli/go.sum"}, SourceLang: "Go", Enrichment: goModCacheEnrichment("/app/cli/go.sum")},
			},
		),

		Entry("pip entries with no lock declare only a required spec",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypePythonPip,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"},
				},
			},
			[]scanner.Cataloger{
				{Name: "python-package-cataloger", Ecosystem: string(config.PackagesDirectiveTypePythonPip), Workdir: "/app", SourcePaths: []string{"/app/requirements.txt"}, SourceLang: "Python"},
			},
		),

		Entry("javascript entries declare node_modules as the license enrichment dir",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeJavaScriptYarn,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "package.json", Lock: "yarn.lock"},
				},
				{
					Type:      config.PackagesDirectiveTypeJavaScriptNpm,
					FileBased: config.FileBasedSpec{Workdir: "/svc", Spec: "package.json", Lock: "package-lock.json"},
				},
				{
					Type:      config.PackagesDirectiveTypeJavaScriptPnpm,
					FileBased: config.FileBasedSpec{Workdir: "/web", Spec: "package.json", Lock: "pnpm-lock.yaml"},
				},
			},
			[]scanner.Cataloger{
				{Name: "javascript-lock-cataloger", Ecosystem: string(config.PackagesDirectiveTypeJavaScriptYarn), Workdir: "/app", SourcePaths: []string{"/app/package.json"}, OptionalSourcePaths: []string{"/app/yarn.lock"}, SourceLang: "JavaScript", Enrichment: nodeModulesEnrichment("/app/node_modules")},
				{Name: "javascript-lock-cataloger", Ecosystem: string(config.PackagesDirectiveTypeJavaScriptNpm), Workdir: "/svc", SourcePaths: []string{"/svc/package.json"}, OptionalSourcePaths: []string{"/svc/package-lock.json"}, SourceLang: "JavaScript", Enrichment: nodeModulesEnrichment("/svc/node_modules")},
				{Name: "javascript-lock-cataloger", Ecosystem: string(config.PackagesDirectiveTypeJavaScriptPnpm), Workdir: "/web", SourcePaths: []string{"/web/package.json"}, OptionalSourcePaths: []string{"/web/pnpm-lock.yaml"}, SourceLang: "JavaScript", Enrichment: nodeModulesEnrichment("/web/node_modules")},
			},
		),

		Entry("ruby entries add an installed-gemspec cataloger for the licenses the lock lacks",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeRubyBundler,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "Gemfile", Lock: "Gemfile.lock"},
				},
				{
					Type:      config.PackagesDirectiveTypeRubyGemspec,
					FileBased: config.FileBasedSpec{Workdir: "/lib", Spec: "app.gemspec"},
				},
			},
			[]scanner.Cataloger{
				{Name: "ruby-gemfile-cataloger", Ecosystem: string(config.PackagesDirectiveTypeRubyBundler), Workdir: "/app", SourcePaths: []string{"/app/Gemfile"}, OptionalSourcePaths: []string{"/app/Gemfile.lock"}, SourceLang: "Ruby"},
				{Name: "ruby-installed-gemspec-cataloger", Ecosystem: string(config.PackagesDirectiveTypeRubyBundler), Workdir: "/app", SourcePaths: []string{"/app/Gemfile"}, OptionalSourcePaths: []string{"/app/Gemfile.lock"}, SourceLang: "Ruby", Enrichment: gemHomeEnrichment("/app", "/app/Gemfile.lock")},
				{Name: "ruby-gemspec-cataloger", Ecosystem: string(config.PackagesDirectiveTypeRubyGemspec), Workdir: "/lib", SourcePaths: []string{"/lib/app.gemspec"}, SourceLang: "Ruby"},
				{Name: "ruby-installed-gemspec-cataloger", Ecosystem: string(config.PackagesDirectiveTypeRubyGemspec), Workdir: "/lib", SourcePaths: []string{"/lib/app.gemspec"}, SourceLang: "Ruby", Enrichment: gemHomeEnrichment("/lib", "")},
			},
		),

		Entry("a ruby entry carries its packages.env into the gem directory enrichment plan",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeRubyBundler,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "Gemfile", Lock: "Gemfile.lock"},
					Env:       map[string]string{"BUNDLE_PATH": "vendor/bundle"},
				},
			},
			[]scanner.Cataloger{
				{Name: "ruby-gemfile-cataloger", Ecosystem: string(config.PackagesDirectiveTypeRubyBundler), Workdir: "/app", Env: map[string]string{"BUNDLE_PATH": "vendor/bundle"}, SourcePaths: []string{"/app/Gemfile"}, OptionalSourcePaths: []string{"/app/Gemfile.lock"}, SourceLang: "Ruby"},
				{Name: "ruby-installed-gemspec-cataloger", Ecosystem: string(config.PackagesDirectiveTypeRubyBundler), Workdir: "/app", Env: map[string]string{"BUNDLE_PATH": "vendor/bundle"}, SourcePaths: []string{"/app/Gemfile"}, OptionalSourcePaths: []string{"/app/Gemfile.lock"}, SourceLang: "Ruby", Enrichment: gemHomeEnrichment("/app", "/app/Gemfile.lock", map[string]string{"BUNDLE_PATH": "vendor/bundle"})},
			},
		),

		Entry("a go-mod entry without a lock has no module cache enrichment to drive",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeGoMod,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "go.mod"},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", SourcePaths: []string{"/app/go.mod"}, SourceLang: "Go"},
			},
		),

		Entry("a go-mod entry carries its packages.env into the module cache enrichment plan",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeGoMod,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
					Env:       map[string]string{"GOPATH": "/opt/build/go"},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", Env: map[string]string{"GOPATH": "/opt/build/go"}, SourcePaths: []string{"/app/go.mod"}, OptionalSourcePaths: []string{"/app/go.sum"}, SourceLang: "Go", Enrichment: goModCacheEnrichment("/app/go.sum", map[string]string{"GOPATH": "/opt/build/go"})},
			},
		),

		Entry("os-pm entries are skipped by buildResolvers per FR-012",
			[]*config.PackagesDirective{
				{
					Type: config.PackagesDirectiveTypeOSPM,
					Spec: config.PackagesSpec{Packages: []string{"curl", "jq"}},
				},
			},
			nil,
		),

		Entry("multiple os-pm entries are skipped by buildResolvers per FR-012",
			[]*config.PackagesDirective{
				{
					Type: config.PackagesDirectiveTypeOSPM,
					Spec: config.PackagesSpec{Packages: []string{"curl", "jq"}},
				},
				{
					Type: config.PackagesDirectiveTypeOSPM,
					Spec: config.PackagesSpec{Packages: []string{"git"}},
				},
			},
			nil,
		),

		Entry("no os-pm packages yields no os-pm cataloger",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeGoMod,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", SourcePaths: []string{"/app/go.mod"}, OptionalSourcePaths: []string{"/app/go.sum"}, SourceLang: "Go", Enrichment: goModCacheEnrichment("/app/go.sum")},
			},
		),

		Entry("a go-mod entry carries the manager it names",
			[]*config.PackagesDirective{
				{
					Type:      config.PackagesDirectiveTypeGoMod,
					FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "go.mod", Manager: "/usr/local/go/bin/go"},
				},
			},
			[]scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", Manager: "/usr/local/go/bin/go", SourcePaths: []string{"/app/go.mod"}, SourceLang: "Go"},
			},
		),

		Entry("nil packages yield no catalogers",
			[]*config.PackagesDirective(nil),
			[]scanner.Cataloger(nil),
		),
	)
})
