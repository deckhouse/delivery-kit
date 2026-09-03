package e2e_build_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

type sbomRepositoryMatrixCase struct {
	name      string
	finalRepo bool
	cacheRepo bool
	identical bool
}

var _ = Describe("SBOM artifact repository matrix", Label("e2e", "sbom", "repository-matrix"), func() {
	DescribeTable("makes artifacts available in every image destination",
		func(ctx SpecContext, testCase sbomRepositoryMatrixCase) {
			setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
			primaryRepo := suite_init.TestRepo(SuiteData.ProjectName + "-matrix-" + testCase.name)
			finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-matrix-" + testCase.name + "-final")
			cacheRepo := suite_init.TestRepo(SuiteData.ProjectName + "-matrix-" + testCase.name + "-cache")
			SuiteData.Stubs.SetEnv("WERF_REPO", primaryRepo)

			SuiteData.InitTestRepo(ctx, "repo_sbom_repository_matrix_"+testCase.name, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_repository_matrix_" + testCase.name)
			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-matrix-"+testCase.name)
			project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			var extraArgs []string
			if testCase.finalRepo {
				extraArgs = append(extraArgs, "--final-repo", finalRepo)
			}
			if testCase.cacheRepo {
				extraArgs = append(extraArgs, "--cache-repo", cacheRepo)
			}
			if testCase.identical {
				extraArgs = append(extraArgs, "--final-repo", primaryRepo, "--cache-repo", primaryRepo)
			}

			_, buildReport := report.NewProjectWithReport(project).BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_repository_matrix_"+testCase.name+".json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{ExtraArgs: extraArgs, Envs: builderEnv}},
			)
			record, found := buildReport.Images["app"]
			Expect(found).To(BeTrue(), "expected app image in build report")
			Expect(record.DockerImageDigest).NotTo(BeEmpty())

			destinations := []string{primaryRepo}
			if testCase.finalRepo && !testCase.identical {
				destinations = append(destinations, finalRepo)
			}
			if testCase.cacheRepo && !testCase.identical {
				destinations = append(destinations, cacheRepo)
			}
			for _, destination := range destinations {
				out := project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--repo", destination, "--digest", record.DockerImageDigest},
					Envs:      builderEnv,
				}})
				Expect(out).To(ContainSubstring("curl"), "SBOM is unavailable in %s", destination)
			}
		},
		Entry("primary only", sbomRepositoryMatrixCase{name: "primary"}),
		Entry("final repository", sbomRepositoryMatrixCase{name: "final", finalRepo: true}),
		Entry("cache repository", sbomRepositoryMatrixCase{name: "cache", cacheRepo: true}),
		Entry("combined final and cache repositories", sbomRepositoryMatrixCase{name: "combined", finalRepo: true, cacheRepo: true}),
		Entry("identical final and cache addresses", sbomRepositoryMatrixCase{name: "identical", finalRepo: true, cacheRepo: true, identical: true}),
	)

	It("restores an SBOM-bearing image from a secondary repository", func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
		secondaryRepo := suite_init.TestRepo(SuiteData.ProjectName + "-matrix-secondary")
		primaryRepo := suite_init.TestRepo(SuiteData.ProjectName + "-matrix-restored")
		SuiteData.InitTestRepo(ctx, "repo_sbom_repository_matrix_secondary", "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_repository_matrix_secondary")
		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-matrix-secondary")
		project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

		reportPath := SuiteData.GetBuildReportPath("sbom_repository_matrix_secondary_source.json")
		_, sourceReport := report.NewProjectWithReport(project).BuildWithReport(ctx, reportPath,
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--repo", secondaryRepo}, Envs: builderEnv}})
		source, found := sourceReport.Images["app"]
		Expect(found).To(BeTrue())
		Expect(source.DockerImageDigest).NotTo(BeEmpty())

		_, restoredReport := report.NewProjectWithReport(project).BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_repository_matrix_secondary_restored.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--repo", primaryRepo, "--secondary-repo", secondaryRepo},
				Envs:      builderEnv,
			}})
		restored, found := restoredReport.Images["app"]
		Expect(found).To(BeTrue())
		Expect(restored.DockerImageDigest).NotTo(BeEmpty())
		Expect(restored.DockerImageDigest).To(Equal(source.DockerImageDigest), fmt.Sprintf("secondary restore changed image digest from %s", source.DockerImageDigest))

		out := project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{
			ExtraArgs: []string{"--repo", primaryRepo, "--digest", restored.DockerImageDigest},
			Envs:      builderEnv,
		}})
		Expect(out).To(ContainSubstring("curl"))
	})
})
