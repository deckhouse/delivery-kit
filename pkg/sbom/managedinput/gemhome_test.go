package managedinput

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/scanner"
)

var _ = Describe("GemHomeDir", func() {
	DescribeTable("resolves the directory RubyGems installs into inside the image",
		func(imageEnv []string, overlay map[string]string, workdir string, bundler bool, expected string) {
			Expect(GemHomeDir(imageEnv, overlay, workdir, bundler)).To(Equal(expected))
		},
		Entry("image sets GEM_HOME", []string{"PATH=/usr/bin", "GEM_HOME=/usr/bundle"}, nil, "/app", true, "/usr/bundle"),
		Entry("BUNDLE_PATH wins over GEM_HOME for bundler", []string{"GEM_HOME=/usr/bundle", "BUNDLE_PATH=/opt/gems"}, nil, "/app", true, "/opt/gems"),
		Entry("gem install ignores BUNDLE_PATH", []string{"GEM_HOME=/usr/bundle", "BUNDLE_PATH=/opt/gems"}, nil, "/app", false, "/usr/bundle"),
		Entry("a relative BUNDLE_PATH is resolved against the workdir", []string{"BUNDLE_PATH=vendor/bundle"}, nil, "/app", true, "/app/vendor/bundle"),
		Entry("neither variable set falls back to the interpreter default", []string{"PATH=/usr/bin"}, nil, "/app", true, "/usr/lib/ruby/gems"),
		Entry("empty environment", nil, nil, "/app", false, "/usr/lib/ruby/gems"),
		Entry("malformed entries are ignored", []string{"NOEQUALS", "GEM_HOME=/usr/bundle"}, nil, "/app", true, "/usr/bundle"),
		Entry("directive BUNDLE_PATH overrides the image GEM_HOME", []string{"GEM_HOME=/usr/bundle"}, map[string]string{"BUNDLE_PATH": "vendor/bundle"}, "/app", true, "/app/vendor/bundle"),
		Entry("directive GEM_HOME overrides the image GEM_HOME", []string{"GEM_HOME=/usr/bundle"}, map[string]string{"GEM_HOME": "/opt/gems"}, "/app", false, "/opt/gems"),
	)
})

var _ = Describe("ResolveEnrichmentRoot", func() {
	It("fills the gem directory of a ruby enrichment plan from the image environment", func() {
		enrichment := gemHomeEnrichment("/app", "/app/Gemfile.lock")
		ResolveEnrichmentRoot(enrichment, []string{"GEM_HOME=/usr/bundle"})
		Expect(enrichment.Root).To(Equal("/usr/bundle"))
	})

	It("leaves a workdir-rooted enrichment plan alone", func() {
		enrichment := nodeModulesEnrichment("/app/node_modules")
		ResolveEnrichmentRoot(enrichment, []string{"GEM_HOME=/usr/bundle"})
		Expect(enrichment.Root).To(Equal("/app/node_modules"))
		Expect(enrichment.Kind).To(Equal(scanner.EnrichmentKindDir))
	})
})

var _ = Describe("GemLockNames", func() {
	It("lists every gem of the bundle once, from every source section, a native gem once for all its platforms", func() {
		lock := `GIT
  remote: https://github.com/rails/thor.git
  revision: 28d17c2e0a084c5d7dbdcb877a581108ef950bd3
  specs:
    thor (1.3.2)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0)
      racc (~> 1.4)
    nokogiri (1.16.0-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.3)
    rails (7.1.3)
      nokogiri (>= 1.8.5)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (= 7.1.3)
  thor!

BUNDLED WITH
   2.6.9
`
		Expect(GemLockNames([]byte(lock))).To(Equal([]string{"thor", "nokogiri", "racc", "rails"}))
	})
})

var _ = Describe("InstalledGemVersions", func() {
	It("reads the installed version of every gem, platform included, from the gemspec file names", func() {
		root := GinkgoT().TempDir()
		specsDir := filepath.Join(root, "3.4.0", "specifications")
		Expect(os.MkdirAll(specsDir, 0o755)).To(Succeed())
		for _, name := range []string{"nokogiri-1.16.0-x86_64-linux.gemspec", "racc-1.7.3.gemspec", "net-http-0.6.0.gemspec", "README"} {
			Expect(os.WriteFile(filepath.Join(specsDir, name), nil, 0o644)).To(Succeed())
		}
		Expect(os.WriteFile(filepath.Join(root, "3.4.0", "stray-1.0.0.gemspec"), nil, 0o644)).To(Succeed())

		Expect(InstalledGemVersions(root)).To(Equal(map[string]string{
			"nokogiri": "1.16.0-x86_64-linux",
			"racc":     "1.7.3",
			"net-http": "0.6.0",
		}))
	})

	It("is empty for a directory the copy never created", func() {
		Expect(InstalledGemVersions(filepath.Join(GinkgoT().TempDir(), "absent"))).To(BeEmpty())
	})
})

var _ = Describe("AlignGemVersions", func() {
	It("gives a native gem the platform variant that is installed and leaves the rest alone", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "a", Name: "nokogiri", Version: "1.16.0", PackageURL: "pkg:gem/nokogiri@1.16.0?package-id=abc"},
			{BOMRef: "b", Name: "racc", Version: "1.7.3", PackageURL: "pkg:gem/racc@1.7.3"},
			{BOMRef: "c", Name: "rails", Version: "7.1.2", PackageURL: "pkg:gem/rails@7.1.2"},
			{BOMRef: "d", Name: "rake", Version: "13.2.1", PackageURL: "pkg:gem/rake@13.2.1"},
		}}

		AlignGemVersions(bom, map[string]string{"nokogiri": "1.16.0-x86_64-linux", "racc": "1.7.3", "rails": "7.1.3"})

		Expect(*bom.Components).To(Equal([]cdx.Component{
			{BOMRef: "a", Name: "nokogiri", Version: "1.16.0-x86_64-linux", PackageURL: "pkg:gem/nokogiri@1.16.0-x86_64-linux?package-id=abc"},
			{BOMRef: "b", Name: "racc", Version: "1.7.3", PackageURL: "pkg:gem/racc@1.7.3"},
			{BOMRef: "c", Name: "rails", Version: "7.1.2", PackageURL: "pkg:gem/rails@7.1.2"},
			{BOMRef: "d", Name: "rake", Version: "13.2.1", PackageURL: "pkg:gem/rake@13.2.1"},
		}))
	})
})

var _ = Describe("DropUninstalledGemVariants", func() {
	It("keeps, of a native gem, only the platform variant the image holds, and every gem without an installed gemspec", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "a", Name: "ffi", Version: "1.17.2", PackageURL: "pkg:gem/ffi@1.17.2"},
			{BOMRef: "b", Name: "ffi", Version: "1.17.2-aarch64-linux-gnu", PackageURL: "pkg:gem/ffi@1.17.2-aarch64-linux-gnu"},
			{BOMRef: "c", Name: "ffi", Version: "1.17.2-x86_64-linux-gnu", PackageURL: "pkg:gem/ffi@1.17.2-x86_64-linux-gnu"},
			{BOMRef: "d", Name: "thor", Version: "1.3.2", PackageURL: "pkg:gem/thor@1.3.2"},
			{BOMRef: "e", Name: "from-git", Version: "0.1.0", PackageURL: "pkg:gem/from-git@0.1.0"},
		}}

		DropUninstalledGemVariants(bom, map[string]string{"ffi": "1.17.2-x86_64-linux-gnu", "thor": "1.3.2"})

		Expect(lo.Map(*bom.Components, func(c cdx.Component, _ int) string { return c.BOMRef })).To(Equal([]string{"c", "d", "e"}))
	})

	It("leaves a scan alone when nothing is known to be installed", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{{BOMRef: "a", Name: "ffi", Version: "1.17.2"}}}
		DropUninstalledGemVariants(bom, nil)
		Expect(*bom.Components).To(HaveLen(1))
	})
})

var _ = Describe("GemspecNames", func() {
	It("lists the gem and its runtime dependencies", func() {
		spec := `Gem::Specification.new do |spec|
  spec.name = "app"
  spec.add_dependency "colorize", "= 1.1.0"
  spec.add_runtime_dependency("thor", "~> 1.3")
  spec.add_development_dependency "rake"
end
`
		Expect(GemspecNames([]byte(spec))).To(Equal([]string{"colorize", "thor", "app"}))
	})
})

var _ = Describe("PruneGemspecs", func() {
	DescribeTable("tells the gem apart from the version in a gemspec file name",
		func(fileName, name string) {
			dir := GinkgoT().TempDir()
			specsDir := filepath.Join(dir, "specifications")
			Expect(os.MkdirAll(specsDir, 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(specsDir, fileName), nil, 0o644)).To(Succeed())

			Expect(PruneGemspecs(dir, []string{name})).To(Succeed())
			_, err := os.Stat(filepath.Join(specsDir, fileName))
			Expect(err).To(Succeed(), "%s names %s", fileName, name)

			Expect(PruneGemspecs(dir, []string{"other"})).To(Succeed())
			_, err = os.Stat(filepath.Join(specsDir, fileName))
			Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue())
		},
		Entry("plain", "rails-7.1.3.gemspec", "rails"),
		Entry("dash in the name", "net-http-0.6.0.gemspec", "net-http"),
		Entry("digit in the name", "ruby2_keywords-0.0.5.gemspec", "ruby2_keywords"),
		Entry("platform suffix", "nokogiri-1.16.0-x86_64-linux.gemspec", "nokogiri"),
		Entry("prerelease", "rails-8.0.0.beta1.gemspec", "rails"),
	)

	It("is a no-op on a directory the copy never created", func() {
		Expect(PruneGemspecs(filepath.Join(GinkgoT().TempDir(), "absent"), []string{"rails"})).To(Succeed())
	})
})
