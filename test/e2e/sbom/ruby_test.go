package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM ruby packages", Label("e2e", "sbom", "ruby", "simple"), func() {
	It("catalogs the gems of a Gemfile.lock with the licenses of their installed gemspecs", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_ruby_bundler"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ruby_bundler")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		sbomtest.AssertHasPURL(bom, "pkg:gem/colorize@1.1.0")
		sbomtest.AssertHasPURL(bom, "pkg:gem/thor@1.3.2")

		// Gemfile.lock carries no licenses; they come from the gemspecs RubyGems writes
		// under $GEM_HOME/specifications, which the installed-gemspec scan reads.
		sbomtest.AssertHasLicense(bom, "colorize", "1.1.0", "GPL-2.0-only")
		sbomtest.AssertHasLicense(bom, "thor", "1.3.2", "MIT")

		// A native gem is listed in the lock once per platform, and installed as the one
		// variant RubyGems picked for the image; its installed gemspec names the version
		// without the platform. Only the installed variant stays, with the license.
		sbomtest.AssertHasLicense(bom, "ffi", "1.17.2-x86_64-linux-gnu", "BSD-3-Clause")
		Expect(sbomtest.FindComponent(bom, "ffi", "1.17.2-aarch64-linux-gnu")).To(BeNil(), "the other platform variant of the lock is not in the image")
		Expect(sbomtest.FindComponent(bom, "ffi", "1.17.2")).To(BeNil(), "the source variant of the lock is not in the image")

		// The gems that ship with the interpreter sit in the same gem directory: default
		// gems (json, bundler) under specifications/default, bundled gems (rake, minitest)
		// right next to the installed ones. They belong to the ruby package, not to the bundle.
		for _, interpreterGem := range []string{"json", "bundler", "rake", "minitest"} {
			sbomtest.AssertNoComponent(bom, interpreterGem)
		}
	})

	It("catalogs the gem a gemspec describes together with its runtime dependencies", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_ruby_gemspec"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ruby_gemspec")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		sbomtest.AssertHasLicense(bom, "werf-sbom-ruby-app", "0.1.0", "MIT")
		sbomtest.AssertHasLicense(bom, "colorize", "1.1.0", "GPL-2.0-only")
		sbomtest.AssertNoComponent(bom, "rake")
	})

	It("build fails when the Gemfile declares a gem its lock does not pin", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_ruby_bundler_stale_lock"
		SuiteData.InitTestRepo(ctx, repoDirname, "negative/ruby_bundler_stale_lock")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		out := werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
			},
		})
		Expect(out).To(ContainSubstring("because frozen mode is set"),
			"expected bundler to refuse updating the lock in frozen mode; got:\n%s", out)
	})
})
