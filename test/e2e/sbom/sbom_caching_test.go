package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

const sbomCachingBaseImageRef = "registry.deckhouse.io/container-factory@sha256:7aac8d97a91ac233b19111aaad9d7bba12b975e620cfa9287b97e0003e4d0a71"

var _ = Describe("SBOM caching (build.sbom.enable)", Label("e2e", "sbom", "caching"), func() {
	DescribeTable("should invalidate stage cache when SBOM is enabled",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			By("initializing")
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_caching"
			fixtureRelPath := "sbom_caching/state0"

			By("first build without build.sbom.enable (default) - stages are cached without SBOM")
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			buildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
			Expect(buildOut).To(ContainSubstring("Building stage"))
			Expect(buildOut).NotTo(ContainSubstring("Use previously built image"))

			By("rebuild without build.sbom.enable - existing cache is reused")
			buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
			Expect(buildOut).To(ContainSubstring("Use previously built image"))
			Expect(buildOut).NotTo(ContainSubstring("Building stage"))

			By("build.sbom.enable=false - backward compatible, existing cache reused")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "sbom_caching/state1")

			buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
			Expect(buildOut).To(ContainSubstring("Use previously built image"))
			Expect(buildOut).NotTo(ContainSubstring("Building stage"))

			By("build.sbom.enable=true - stage cache is invalidated, stages rebuilt with SBOM")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "sbom_caching/state2")

			buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
			Expect(buildOut).To(ContainSubstring("Building stage"))

			By("rebuild with build.sbom.enable=true - cache is reused")
			removeOut, err := utils.RunCommand(ctx, testRepoPath, "docker", "image", "rm", sbomCachingBaseImageRef)
			if err != nil {
				Expect(string(removeOut)).To(ContainSubstring("No such image"))
			}
			buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
			Expect(buildOut).To(ContainSubstring("Pulling base image " + sbomCachingBaseImageRef))
			Expect(buildOut).To(ContainSubstring("Use previously built image"))
			Expect(buildOut).NotTo(ContainSubstring("Building stage"))
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{
			ContainerBackendMode: "vanilla-docker",
		}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{
			ContainerBackendMode: "buildkit-docker",
		}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{
			ContainerBackendMode: "native-rootless",
		}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{
			ContainerBackendMode: "native-chroot",
		}}),
	)
})
