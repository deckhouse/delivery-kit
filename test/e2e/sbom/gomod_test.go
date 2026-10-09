package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM go-mod packages", Label("e2e", "sbom", "gomod", "simple"), func() {
	It("resolves a local 'replace' directive to a version in the BOM and keeps a module replace intact", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_inject_gomod_replace"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/gomod_replace")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		utils.RunSucceedCommand(ctx, testRepoPath, "git", "tag", "v1.0.0")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		mylib := sbomtest.FindComponent(bom, "example.com/mylib", "v1.0.0")
		Expect(mylib).NotTo(BeNil(),
			"expected example.com/mylib@v1.0.0 (resolved from local replace via git tag) not found in BOM")

		// A module replaced by another module needs no resolution: syft catalogs it under
		// the replacement's path and version.
		sbomtest.AssertHasComponent(bom, "github.com/alecthomas/kingpin", "v1.3.8-0.20200323085623-b6657d9477a6")
	})

	It("keeps the license of a registry module read from the module cache", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_inject_gomod_license"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/gomod_license")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		sbomtest.AssertHasComponent(bom, "github.com/pkg/errors", "v0.9.1")

		// go.mod/go.sum carry no license; syft reads it from the module's LICENSE file in
		// the module cache ($GOPATH/pkg/mod). The targeted scan must keep that enrichment.
		sbomtest.AssertHasLicense(bom, "github.com/pkg/errors", "v0.9.1", "BSD-2-Clause")
	})

	It("keeps a module license when packages.env overrides GOPATH away from the image default", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_inject_gomod_gopath"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/gomod_gopath")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)

		// packages.env.GOPATH=/opt/build/go moves the module cache there; enrichment must
		// read the license from the overridden path, not the image's /go/pkg/mod.
		sbomtest.AssertHasLicense(bom, "github.com/pkg/errors", "v0.9.1", "BSD-2-Clause")
	})
})
