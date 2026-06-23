package e2e_build_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

const sbomProcessingPrefix = "SBOM processing"

var _ = Describe("GOST SBOM fields", Label("e2e", "build", "sbom", "gost", "simple"), func() {
	DescribeTable("should succeed with registry-only SBOM for GOST fields",
		func(ctx SpecContext, testOpts simpleTestOptions, fixtureRelPath, repoDirname string) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			By("building image")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, _ := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath(repoDirname+".json"), nil)
			Expect(buildOut).To(ContainSubstring("Building stage"))
			Expect(buildOut).To(ContainSubstring(sbomProcessingPrefix))
		},
		Entry("default values using Vanilla Docker",
			simpleTestOptions{setupEnvOptions{
				ContainerBackendMode: "vanilla-docker",
				WithLocalRepo:        true,
			}},
			"sbom/gost_defaults",
			"gost-defaults",
		),
		Entry("default values using BuildKit Docker",
			simpleTestOptions{setupEnvOptions{
				ContainerBackendMode: "buildkit-docker",
				WithLocalRepo:        true,
			}},
			"sbom/gost_defaults",
			"gost-defaults",
		),
		Entry("image override meta using Vanilla Docker",
			simpleTestOptions{setupEnvOptions{
				ContainerBackendMode: "vanilla-docker",
				WithLocalRepo:        true,
			}},
			"sbom/gost_meta_image",
			"gost-meta-image",
		),
		Entry("image override meta using BuildKit Docker",
			simpleTestOptions{setupEnvOptions{
				ContainerBackendMode: "buildkit-docker",
				WithLocalRepo:        true,
			}},
			"sbom/gost_meta_image",
			"gost-meta-image",
		),
	)
})

var _ = Describe("SBOM go-replace", Label("e2e", "build", "sbom", "go-replace", "simple"), func() {
	DescribeTable("should succeed with registry-only SBOM for go-replace",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo_sbom_go_replace"
			fixtureRelPath := "sbom/go_replace"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "tag", "v1.0.0")

			By("building and pushing builder-base image to local registry")
			builderBaseRef := fmt.Sprintf("%s/golang-builder:test", suite_init.TestRegistry())
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "build", "-t", builderBaseRef, "-f", "Dockerfile.builder-base", ".")
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "push", builderBaseRef)

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			reportProject := report.NewProjectWithReport(werfProject)
			buildOpts := &werf.WithReportOptions{
				CommonOptions: werf.CommonOptions{
					Envs: []string{
						fmt.Sprintf("BUILDER_BASE_IMAGE=%s", builderBaseRef),
					},
				},
			}
			buildOut, _ := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_sbom_go_replace.json"), buildOpts)
			Expect(buildOut).To(ContainSubstring("Building stage"))
			Expect(buildOut).To(ContainSubstring(sbomProcessingPrefix))
		},
		Entry("with local repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using BuildKit Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)
})
