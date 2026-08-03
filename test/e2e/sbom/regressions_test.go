package e2e_build_test

import (
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM regression", Label("e2e", "sbom", "regression", "simple"), func() {
	DescribeTable("manifest annotation preservation: fallback index descriptors carry image-name annotation",
		Label("annotation-consistency"),
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_manifest_annotation"
			SuiteData.InitTestRepo(ctx, repoDirname, "regressions/manifest_annotation")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-manifest-annotation-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("manifest_annotation.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			// Both images must share the same digest (same from + same packages),
			// which means they share the same fallback index tag.
			digests := map[string]string{}
			for name, rec := range buildReport.Images {
				Expect(rec.DockerImageDigest).NotTo(BeEmpty(),
					"image %q has no digest in build report", name)
				digests[name] = rec.DockerImageDigest
			}
			Expect(digests).To(HaveLen(2), "expected exactly 2 images in build report")

			sharedDigest := digests["frontend"]
			Expect(sharedDigest).To(Equal(digests["backend"]),
				"expected frontend and backend to share the same digest; frontend=%q backend=%q",
				sharedDigest, digests["backend"])

			// Each image keeps its own fallback index tag, so that images sharing a
			// digest cannot overwrite each other's SBOM entry. Verify the tags
			// directly via go-containerregistry, without relying on werf commands.
			repo := os.Getenv("WERF_REPO")
			Expect(repo).NotTo(BeEmpty(), "WERF_REPO must be set")

			ropts := []remote.Option{
				remote.WithContext(ctx),
				remote.WithAuth(authn.Anonymous),
			}

			for _, imageName := range []string{"frontend", "backend"} {
				tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(sharedDigest, imageName), name.Insecure)
				Expect(err).NotTo(HaveOccurred())

				idx, err := remote.Index(tagRef, ropts...)
				Expect(err).NotTo(HaveOccurred(),
					"failed to pull fallback index tag %q for image %q", tagRef, imageName)

				im, err := idx.IndexManifest()
				Expect(err).NotTo(HaveOccurred())

				entries := map[string]bool{}
				for _, desc := range im.Manifests {
					if desc.ArtifactType == sbomImage.DSSEMediaType {
						entries[desc.Annotations[image.WerfImageNameAnnotation]] = true
					}
				}

				Expect(entries).To(HaveKey(imageName),
					"fallback index %q missing annotated entry for image %q, got %v", tagRef, imageName, entries)
			}
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
