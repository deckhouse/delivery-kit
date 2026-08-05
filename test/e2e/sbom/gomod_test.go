package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM go-mod packages", Label("e2e", "sbom", "gomod", "simple"), func() {
	DescribeTable("resolves local 'replace' directive to a version in the BOM",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

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
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
