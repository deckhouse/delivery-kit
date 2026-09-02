package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM artifact repository failures", Label("e2e", "sbom", "artifact-failures"), func() {
	It("rejects artifact generation without a registry before image work", func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
		SuiteData.Stubs.UnsetEnv("WERF_REPO")
		SuiteData.Stubs.UnsetEnv("WERF_FINAL_REPO")

		SuiteData.InitTestRepo(ctx, "repo_sbom_local_only", "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_local_only")
		project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

		out, err := project.BuildWithErr(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{
			Envs: []string{"BUILDER_BASE_IMAGE=registry.example/builder:latest"},
		}})

		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("requires a container registry"))
		Expect(out).NotTo(ContainSubstring("Building stage"))
	})

	It("fails when the final artifact repository is unavailable", func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
		finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-unavailable-final")
		SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

		SuiteData.InitTestRepo(ctx, "repo_sbom_unavailable_final", "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_unavailable_final")
		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-unavailable-final-builder")
		builderEnv = append(builderEnv, "WERF_FINAL_REPO=127.0.0.1:1/unreachable/final")
		project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

		out, err := project.BuildWithErr(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("unable to init storage manager cache"))
		Expect(out).To(ContainSubstring("127.0.0.1:1/unreachable/final"))
	})
})
