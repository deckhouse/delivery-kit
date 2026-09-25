package e2e_build_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM caching (build.sbom.enable)", Label("e2e", "sbom", "caching"), func() {
	It("should invalidate stage cache when SBOM is enabled", func(ctx SpecContext) {
		By("initializing")
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_caching"
		fixtureRelPath := "sbom_caching/state0"

		By("first build without build.sbom.enable (default) - stages are cached without SBOM")
		SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-caching-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		buildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
		Expect(buildOut).To(ContainSubstring("Building stage"))
		Expect(buildOut).NotTo(ContainSubstring("Use previously built image"))

		By("rebuild without build.sbom.enable - existing cache is reused")
		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
		Expect(buildOut).To(ContainSubstring("Use previously built image"))
		Expect(buildOut).NotTo(ContainSubstring("Building stage"))

		By("build.sbom.enable=false - backward compatible, existing cache reused")
		SuiteData.UpdateTestRepo(ctx, repoDirname, "sbom_caching/state1")

		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
		Expect(buildOut).To(ContainSubstring("Use previously built image"))
		Expect(buildOut).NotTo(ContainSubstring("Building stage"))

		By("build.sbom.enable=true - stage cache is invalidated, stages rebuilt with SBOM")
		SuiteData.UpdateTestRepo(ctx, repoDirname, "sbom_caching/state2")

		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
		Expect(buildOut).To(ContainSubstring("Building stage"))

		By("rebuild with build.sbom.enable=true - cache is reused")
		builderBaseRef := fmt.Sprintf("%s/%s:test", suite_init.TestRegistry(), "sbom-caching-builder")
		removeOut, err := utils.RunCommand(ctx, testRepoPath, "docker", "image", "rm", builderBaseRef)
		if err != nil {
			Expect(string(removeOut)).To(ContainSubstring("No such image"))
		}
		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
		Expect(buildOut).To(ContainSubstring("Pulling base image " + builderBaseRef))
		Expect(buildOut).To(ContainSubstring("Use previously built image"))
		Expect(buildOut).NotTo(ContainSubstring("Building stage"))
	})
})
