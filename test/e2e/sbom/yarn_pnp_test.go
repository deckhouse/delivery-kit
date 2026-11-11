package e2e_build_test

import (
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = ginkgo.Describe("SBOM Yarn Plug'n'Play shipped-scope", ginkgo.Label("e2e", "sbom", "yarn", "yarn-pnp"), func() {
	ginkgo.It("evidences packages by their cache zips through imports, cache reuse and SBOM regeneration", func(ctx ginkgo.SpecContext) {
		setupSbomBuildEnv()
		repoDirname := "repo_sbom_yarn_pnp"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/yarn_pnp")
		repoPath := SuiteData.GetTestRepoPath(repoDirname)
		project := werf.NewProject(SuiteData.WerfBinPath, repoPath)

		ginkgo.By("installing with the project and the global cache, then importing one zip")
		out := project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		gomega.Expect(out).To(gomega.ContainSubstring("image donor: SBOM processing"))
		archives := assertYarnPnPOutputs(ctx, project, repoPath)
		initial := assertYarnPnPImages(ctx, project, archives)
		donorDigest := stagesImageDigestOf(ctx, project, "donor")

		ginkgo.By("reusing both image and SBOM caches")
		out = project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		gomega.Expect(out).To(gomega.ContainSubstring("Use previously built image"))
		gomega.Expect(out).NotTo(gomega.ContainSubstring("Building stage"))
		gomega.Expect(out).To(gomega.ContainSubstring("image donor: Use previously generated SBOM from registry"))
		gomega.Expect(assertYarnPnPImages(ctx, project, archives)).To(gomega.Equal(initial))

		ginkgo.By("deleting only the donor's SBOM discovery index, not its cached image")
		repo := os.Getenv("WERF_REPO")
		gomega.Expect(repo).NotTo(gomega.BeEmpty())
		tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(donorDigest), name.Insecure)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		desc, err := remote.Head(tagRef, insecureRemoteOptions(ctx)...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Delete(tagRef.Context().Digest(desc.Digest.String()), insecureRemoteOptions(ctx)...)).To(gomega.Succeed())
		expectNoSbomArtifact(ctx, repo, donorDigest)

		ginkgo.By("regenerating the donor's zip evidence from cached stage ancestry without rerunning the install")
		out = project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		gomega.Expect(out).To(gomega.ContainSubstring("image donor: SBOM processing"))
		gomega.Expect(out).To(gomega.ContainSubstring("Use previously built image"))
		gomega.Expect(out).NotTo(gomega.ContainSubstring("Building stage"))
		gomega.Expect(stagesImageDigestOf(ctx, project, "donor")).To(gomega.Equal(donorDigest))
		gomega.Expect(assertYarnPnPImages(ctx, project, archives)).To(gomega.Equal(initial))
	})
})
