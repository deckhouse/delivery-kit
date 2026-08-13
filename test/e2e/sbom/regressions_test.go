package e2e_build_test

import (
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
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

			// Pull the fallback index and verify annotations directly
			// via go-containerregistry, without relying on werf commands.
			repo := os.Getenv("WERF_REPO")
			Expect(repo).NotTo(BeEmpty(), "WERF_REPO must be set")

			tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(sharedDigest), name.Insecure)
			Expect(err).NotTo(HaveOccurred())

			ropts := []remote.Option{
				remote.WithContext(ctx),
				remote.WithAuth(authn.Anonymous),
			}

			idx, err := remote.Index(tagRef, ropts...)
			Expect(err).NotTo(HaveOccurred(),
				"failed to pull fallback index tag %q", tagRef)

			im, err := idx.IndexManifest()
			Expect(err).NotTo(HaveOccurred())

			// Build a lookup of image-name annotations from the index manifest.
			entries := map[string]bool{}
			for _, desc := range im.Manifests {
				if desc.ArtifactType == attestation.DSSEMediaType {
					imgName := desc.Annotations[image.WerfImageNameAnnotation]
					entries[imgName] = true
				}
			}

			Expect(entries).To(HaveLen(2),
				"expected 2 annotated entries in fallback index, got %d", len(entries))
			Expect(entries).To(HaveKey("frontend"),
				"fallback index missing annotation for frontend")
			Expect(entries).To(HaveKey("backend"),
				"fallback index missing annotation for backend")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
