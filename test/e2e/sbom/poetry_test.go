package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM python-poetry packages", Label("e2e", "sbom", "poetry", "simple"), func() {
	DescribeTable("catalogs poetry.lock dependencies into the BOM",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_python_poetry_simple"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/poetry_simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-python-poetry-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			buildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(buildOut).NotTo(ContainSubstring("alternative manager poetry is already installed"))
			managerAbsentOut := werfProject.RunCommand(ctx, []string{"run", "app", "--", "sh", "-c", "command -v poetry >/dev/null 2>&1 && exit 1; for scope in /tmp/werf-packages-*; do test -e \"$scope\" && exit 1; done; exit 0"}, werf.CommonOptions{Envs: builderEnv})
			Expect(managerAbsentOut).NotTo(ContainSubstring("alternative manager"))

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			requests := sbomtest.FindComponent(bom, "requests", "2.32.3")
			Expect(requests).NotTo(BeNil(),
				"expected requests@2.32.3 (from poetry.lock) not found in BOM")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
