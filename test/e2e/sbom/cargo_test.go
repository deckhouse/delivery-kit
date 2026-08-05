package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM rust-cargo packages", Label("e2e", "sbom", "cargo", "simple"), func() {
	DescribeTable("catalogs Cargo.lock dependencies into the BOM",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_rust_cargo_simple"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/cargo_simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-rust-cargo-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			anyhow := sbomtest.FindComponent(bom, "anyhow", "1.0.86")
			Expect(anyhow).NotTo(BeNil(),
				"expected anyhow@1.0.86 (from Cargo.lock) not found in BOM")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
