package e2e_build_test

import (
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM artifact repository failures", Label("e2e", "sbom", "artifact-failures"), func() {
	It("publishes SBOM artifacts into a separate cache repository namespace", func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
		cacheRepo := suite_init.TestRepo(SuiteData.ProjectName + "-cache")
		SuiteData.InitTestRepo(ctx, "repo_sbom_cache_repo", "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_cache_repo")
		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-cache-repo-builder")
		project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(project)
		_, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("sbom_cache_repo.json"), &werf.WithReportOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--cache-repo", cacheRepo}, Envs: builderEnv},
		})

		record, found := buildReport.Images["app"]
		Expect(found).To(BeTrue())
		Expect(record.DockerImageDigest).NotTo(BeEmpty())
		cacheOut := project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{
			ExtraArgs: []string{"--repo", cacheRepo, "--digest", record.DockerImageDigest}, Envs: builderEnv,
		}})
		Expect(cacheOut).To(ContainSubstring("curl"))
	})

	It("continues successfully when the cache repository is unavailable", func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
		SuiteData.InitTestRepo(ctx, "repo_sbom_unavailable_cache", "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_unavailable_cache")
		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-unavailable-cache-builder")
		project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(project)
		_, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("sbom_unavailable_cache.json"), &werf.WithReportOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--cache-repo", "127.0.0.1:1/unreachable/cache"}, Envs: builderEnv},
		})

		record, found := buildReport.Images["app"]
		Expect(found).To(BeTrue())
		primaryOut := project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{
			ExtraArgs: []string{"--repo", suite_init.TestRepo(SuiteData.ProjectName), "--digest", record.DockerImageDigest}, Envs: builderEnv,
		}})
		Expect(primaryOut).To(ContainSubstring("curl"))
	})
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

	It("rejects a secondary image whose artifact fallback index is missing", func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})
		secondaryRepo := suite_init.TestRepo(SuiteData.ProjectName + "-secondary")
		primaryRepo := suite_init.TestRepo(SuiteData.ProjectName + "-restored")
		SuiteData.InitTestRepo(ctx, "repo_sbom_missing_secondary_artifact", "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath("repo_sbom_missing_secondary_artifact")
		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-secondary-builder")
		project := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(project)
		_, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("sbom_secondary_source.json"), &werf.WithReportOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--repo", secondaryRepo}, Envs: builderEnv},
		})
		record, found := buildReport.Images["app"]
		Expect(found).To(BeTrue())

		ref, err := name.NewTag(secondaryRepo+":"+artifact.FallbackTag(record.DockerImageDigest), name.Insecure)
		Expect(err).NotTo(HaveOccurred())
		fallbackDesc, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
		Expect(err).NotTo(HaveOccurred())
		fallbackDigest, err := name.NewDigest(secondaryRepo+"@"+fallbackDesc.Digest.String(), name.Insecure)
		Expect(err).NotTo(HaveOccurred())
		Expect(remote.Delete(fallbackDigest, remote.WithAuth(authn.Anonymous))).To(Succeed())

		out, err := project.BuildWithErr(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{
			ExtraArgs: []string{"--repo", primaryRepo, "--secondary-repo", secondaryRepo}, Envs: builderEnv,
		}})
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("has incomplete artifacts"))
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
