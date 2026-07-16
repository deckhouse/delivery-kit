package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM javascript-npm packages", Label("e2e", "sbom", "npm", "simple"), func() {
	DescribeTable("catalogs package-lock.json dependencies into the BOM",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_npm_simple"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/npm_simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-npm-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			lodash := sbomtest.FindComponent(bom, "lodash", "4.17.21")
			Expect(lodash).NotTo(BeNil(),
				"expected lodash@4.17.21 (from package-lock.json) not found in BOM")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
