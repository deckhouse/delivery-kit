package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM go-mod packages", Label("e2e", "sbom", "gomod", "simple"), func() {
	It("resolves local 'replace' directive to a version in the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_inject_gomod_replace"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/gomod_replace")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		utils.RunSucceedCommand(ctx, testRepoPath, "git", "tag", "v1.0.0")

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-inject-gomod-replace-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
				Envs:      builderEnv,
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		mylib := sbomtest.FindComponent(bom, "example.com/mylib", "v1.0.0")
		Expect(mylib).NotTo(BeNil(),
			"expected example.com/mylib@v1.0.0 (resolved from local replace via git tag) not found in BOM")
	})

	It("keeps the license of a registry module read from the module cache", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_inject_gomod_license"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/gomod_license")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-inject-gomod-license-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
				Envs:      builderEnv,
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

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-inject-gomod-gopath-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
				Envs:      builderEnv,
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)

		// packages.env.GOPATH=/opt/build/go moves the module cache there; enrichment must
		// read the license from the overridden path, not the image's /go/pkg/mod.
		sbomtest.AssertHasLicense(bom, "github.com/pkg/errors", "v0.9.1", "BSD-2-Clause")
	})
})
