package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM javascript-yarn packages with an explicit manager", Label("e2e", "sbom", "yarn", "simple"), func() {
	DescribeTable("installs dependencies with a yarn absent from the builder image",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_yarn_manager"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/yarn_manager")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-yarn-manager-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			Expect(sbomtest.FindComponent(bom, "lodash", "4.17.21")).NotTo(BeNil(),
				"expected lodash@4.17.21 (from yarn.lock) not found in BOM")
			Expect(sbomtest.FindComponent(bom, "yarn", "1.22.22")).NotTo(BeNil(),
				"expected the bootstrapped yarn@1.22.22 not found in BOM")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
