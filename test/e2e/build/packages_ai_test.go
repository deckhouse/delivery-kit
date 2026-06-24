package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("Build with os-pm packages SBOM (AI)", Label("e2e", "build", "sbom", "packages"), func() {
	DescribeTable("should include pm-collected binary packages in the image SBOM",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			repoDirname := "repo-os-pm-packages"

			By("preparing test repo")
			SuiteData.InitTestRepo(ctx, repoDirname, "sbom/packages/state0")

			By("building image with SBOM")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			buildOut := werfProject.Build(ctx, nil)
			Expect(buildOut).To(ContainSubstring(sbomProcessingPrefix))

			By("retrieving the image SBOM from the registry")
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"stapel"}},
			})

			By("asserting the declared os-pm package is present")
			Expect(sbomOut).To(ContainSubstring("flant-marker"))
			Expect(sbomOut).To(ContainSubstring("pkg:generic/flant-marker@9.9.9"))

			By("asserting the transitive os-pm dependency is present")
			Expect(sbomOut).To(ContainSubstring("flant-lib"))
			Expect(sbomOut).To(ContainSubstring("pkg:generic/flant-lib@2.0.0"))
		},
		Entry("with local repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode: "vanilla-docker",
			WithLocalRepo:        true,
		}}),
	)
})
