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

var _ = ginkgo.Describe("SBOM produced-binaries shipped-scope", ginkgo.Label("e2e", "sbom", "produced-binaries"), func() {
	ginkgo.It("retains only the imported binary's dependencies through regeneration and a second import", func(ctx ginkgo.SpecContext) {
		setupSbomBuildEnv()
		repoDirname := "repo_sbom_produced_binaries"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/produced_binaries")
		project := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))

		ginkgo.By("building two binaries and importing only the cobra binary")
		out := project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		gomega.Expect(out).To(gomega.ContainSubstring("image donor: SBOM processing"))
		initial := assertProducedBinaryImages(ctx, project)
		donorDigest := stagesImageDigestOf(ctx, project, "donor")

		ginkgo.By("reusing both image and SBOM caches")
		out = project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		gomega.Expect(out).To(gomega.ContainSubstring("Use previously built image"))
		gomega.Expect(out).NotTo(gomega.ContainSubstring("Building stage"))
		gomega.Expect(out).To(gomega.ContainSubstring("image donor: Use previously generated SBOM from registry"))
		gomega.Expect(assertProducedBinaryImages(ctx, project)).To(gomega.Equal(initial))

		ginkgo.By("deleting only the donor's SBOM discovery index, not its cached image")
		repo := os.Getenv("WERF_REPO")
		gomega.Expect(repo).NotTo(gomega.BeEmpty())
		tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(donorDigest), name.Insecure)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		desc, err := remote.Head(tagRef, insecureRemoteOptions(ctx)...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Delete(tagRef.Context().Digest(desc.Digest.String()), insecureRemoteOptions(ctx)...)).To(gomega.Succeed())
		expectNoSbomArtifact(ctx, repo, donorDigest)

		ginkgo.By("regenerating donor evidence from cached stage ancestry without executing a build stage")
		out = project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		gomega.Expect(out).To(gomega.ContainSubstring("image donor: SBOM processing"))
		gomega.Expect(out).To(gomega.ContainSubstring("Use previously built image"))
		gomega.Expect(out).NotTo(gomega.ContainSubstring("Building stage"))
		gomega.Expect(stagesImageDigestOf(ctx, project, "donor")).To(gomega.Equal(donorDigest))
		gomega.Expect(assertProducedBinaryImages(ctx, project)).To(gomega.Equal(initial))
	})
})
