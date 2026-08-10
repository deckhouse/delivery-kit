package e2e_build_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
	"github.com/werf/werf/v2/test/pkg/report"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM multi-platform", Label("e2e", "sbom", "multiplatform", "simple"), func() {
	DescribeTable("per-platform SBOM generation: build → per-platform artifacts → cache",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			platforms := []string{"linux/amd64", "linux/386"}

			repoDirname := "repo_sbom_multiplatform"
			SuiteData.InitTestRepo(ctx, repoDirname, "multiplatform")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildMultiplatformTrustedBuilderBase(ctx, testRepoPath, "sbom-multiplatform-builder", platforms)

			SuiteData.Stubs.SetEnv("WERF_ENABLE_REPORT_BY_PLATFORM", "1")

			By("building the multi-platform image with SBOM enabled")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_multiplatform.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			repo := suite_init.TestRepo(SuiteData.ProjectName)

			byPlatform := buildReport.ImagesByPlatform["app"]
			Expect(byPlatform).To(HaveLen(len(platforms)), "expected a build report record per platform")

			indexDigest := buildReport.Images["app"].DockerImageDigest
			Expect(indexDigest).NotTo(BeEmpty())

			By("verifying each platform manifest has its own SBOM artifact")
			subjectDigests := map[string]string{}
			for _, platform := range platforms {
				record, hasRecord := byPlatform[platform]
				Expect(hasRecord).To(BeTrue(), "no build report record for platform %s", platform)

				platformDigest := record.DockerImageDigest
				Expect(platformDigest).NotTo(BeEmpty())
				Expect(platformDigest).NotTo(Equal(indexDigest))

				desc, payload := fetchSingleSbomArtifact(ctx, repo, platformDigest)

				Expect(desc.Annotations[image.WerfPlatformAnnotation]).To(Equal(platform),
					"artifact platform annotation must match the scanned platform")
				Expect(desc.Annotations[image.WerfChecksumAnnotation]).NotTo(BeEmpty())
				Expect(desc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))

				subjectDigest := mustExtractInTotoSubjectDigest(payload)
				Expect(subjectDigest).To(Equal(platformDigest),
					"in-toto subject must be the platform manifest digest")

				subjectDigests[platform] = subjectDigest
			}

			Expect(subjectDigests["linux/amd64"]).NotTo(Equal(subjectDigests["linux/386"]),
				"platform SBOMs must attest distinct platform manifests")

			By("verifying no SBOM artifact is attached to the index digest")
			expectNoSbomArtifact(ctx, repo, indexDigest)

			By("verifying the second build reuses per-platform SBOMs from registry")
			rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(strings.Count(rebuildOut, "Use previously generated SBOM from registry")).To(BeNumerically(">=", len(platforms)),
				"each platform SBOM must be served from cache on rebuild")
		},
		Entry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
	)

	DescribeTable("per-platform SBOM with os-pm packages: pm.lock components land in every platform SBOM",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			platforms := []string{"linux/amd64", "linux/386"}

			repoDirname := "repo_sbom_multiplatform_packages"
			SuiteData.InitTestRepo(ctx, repoDirname, "multiplatform_packages")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildMultiplatformTrustedBuilderBase(ctx, testRepoPath, "sbom-multiplatform-pkg-builder", platforms)

			SuiteData.Stubs.SetEnv("WERF_ENABLE_REPORT_BY_PLATFORM", "1")

			By("building the multi-platform image with os-pm packages and SBOM enabled")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_multiplatform_packages.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			repo := suite_init.TestRepo(SuiteData.ProjectName)

			byPlatform := buildReport.ImagesByPlatform["app"]
			Expect(byPlatform).To(HaveLen(len(platforms)), "expected a build report record per platform")

			By("verifying every platform SBOM carries the pm.lock components")
			for _, platform := range platforms {
				record, hasRecord := byPlatform[platform]
				Expect(hasRecord).To(BeTrue(), "no build report record for platform %s", platform)

				desc, payload := fetchSingleSbomArtifact(ctx, repo, record.DockerImageDigest)
				Expect(desc.Annotations[image.WerfPlatformAnnotation]).To(Equal(platform))

				subjectDigest := mustExtractInTotoSubjectDigest(payload)
				Expect(subjectDigest).To(Equal(record.DockerImageDigest),
					"in-toto subject must be the platform manifest digest")

				bom := mustExtractCycloneDXBOM(payload)
				sbomtest.AssertHasComponent(bom, "curl", "8.12.1")
			}
		},
		Entry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
	)
})

func buildMultiplatformTrustedBuilderBase(ctx SpecContext, testRepoPath, refSlug string, platforms []string) []string {
	builderBaseRef := fmt.Sprintf("%s/%s:test", suite_init.TestRegistry(), refSlug)

	var adds []mutate.IndexAddendum
	for _, platform := range platforms {
		platformTag := builderBaseRef + "-" + strings.ReplaceAll(platform, "/", "-")
		utils.RunSucceedCommand(ctx, testRepoPath, "docker", "build",
			"--platform", platform,
			"-t", platformTag,
			"-f", "Dockerfile.builder-base", ".")
		utils.RunSucceedCommand(ctx, testRepoPath, "docker", "push", platformTag)

		platformRef, err := name.ParseReference(platformTag, name.Insecure)
		Expect(err).NotTo(HaveOccurred())
		img, err := remote.Image(platformRef, insecureRemoteOptions(ctx)...)
		Expect(err).NotTo(HaveOccurred())

		parts := strings.SplitN(platform, "/", 3)
		Expect(len(parts)).To(BeNumerically(">=", 2))
		platformSpec := &v1.Platform{OS: parts[0], Architecture: parts[1]}
		if len(parts) == 3 {
			platformSpec.Variant = parts[2]
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: platformSpec}})
	}

	idx := mutate.AppendManifests(empty.Index, adds...)
	idxRef, err := name.ParseReference(builderBaseRef, name.Insecure)
	Expect(err).NotTo(HaveOccurred())
	Expect(remote.WriteIndex(idxRef, idx, insecureRemoteOptions(ctx)...)).To(Succeed())

	return []string{
		fmt.Sprintf("BUILDER_BASE_IMAGE=%s", builderBaseRef),
		"WERF_E2E_ALLOW_LOCAL_BUILDER_IMAGES=true",
	}
}

func insecureRemoteOptions(ctx SpecContext) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	}
}

func pullSbomFallbackIndexManifests(ctx SpecContext, repo, parentDigest string) ([]v1.Descriptor, bool) {
	tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(parentDigest), name.Insecure)
	Expect(err).NotTo(HaveOccurred())

	idx, err := remote.Index(tagRef, insecureRemoteOptions(ctx)...)
	if err != nil {
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == 404 {
			return nil, false
		}
		Expect(err).NotTo(HaveOccurred())
	}

	im, err := idx.IndexManifest()
	Expect(err).NotTo(HaveOccurred())

	var dsseDescs []v1.Descriptor
	for _, desc := range im.Manifests {
		if desc.ArtifactType == sbomImage.DSSEMediaType {
			dsseDescs = append(dsseDescs, desc)
		}
	}
	return dsseDescs, true
}

func fetchSingleSbomArtifact(ctx SpecContext, repo, parentDigest string) (v1.Descriptor, []byte) {
	dsseDescs, found := pullSbomFallbackIndexManifests(ctx, repo, parentDigest)
	Expect(found).To(BeTrue(), "no fallback tag for digest %s", parentDigest)
	Expect(dsseDescs).To(HaveLen(1), "expected exactly one SBOM artifact for digest %s", parentDigest)

	artifactRef, err := name.NewDigest(repo+"@"+dsseDescs[0].Digest.String(), name.Insecure)
	Expect(err).NotTo(HaveOccurred())

	img, err := remote.Image(artifactRef, insecureRemoteOptions(ctx)...)
	Expect(err).NotTo(HaveOccurred())

	layers, err := img.Layers()
	Expect(err).NotTo(HaveOccurred())
	Expect(layers).To(HaveLen(1))

	rc, err := layers[0].Compressed()
	Expect(err).NotTo(HaveOccurred())
	defer rc.Close()

	payload, err := io.ReadAll(rc)
	Expect(err).NotTo(HaveOccurred())

	return dsseDescs[0], payload
}

func expectNoSbomArtifact(ctx SpecContext, repo, parentDigest string) {
	dsseDescs, found := pullSbomFallbackIndexManifests(ctx, repo, parentDigest)
	if !found {
		return
	}
	Expect(dsseDescs).To(BeEmpty(), "no SBOM artifact must be attached to the index digest %s", parentDigest)
}

func mustExtractInTotoSubjectDigest(dsseEnvelope []byte) string {
	var envelope struct {
		Payload []byte `json:"payload"`
	}
	Expect(json.Unmarshal(dsseEnvelope, &envelope)).To(Succeed())

	var statement struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	Expect(json.Unmarshal(envelope.Payload, &statement)).To(Succeed())
	Expect(statement.Subject).To(HaveLen(1))

	hex, hasSha256 := statement.Subject[0].Digest["sha256"]
	Expect(hasSha256).To(BeTrue(), "in-toto subject must carry a sha256 digest")
	return "sha256:" + hex
}

func mustExtractCycloneDXBOM(dsseEnvelope []byte) *cdx.BOM {
	var envelope struct {
		Payload []byte `json:"payload"`
	}
	Expect(json.Unmarshal(dsseEnvelope, &envelope)).To(Succeed())

	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	Expect(json.Unmarshal(envelope.Payload, &statement)).To(Succeed())
	Expect(statement.Predicate).NotTo(BeEmpty(), "in-toto statement must carry a predicate")

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(statement.Predicate)
	Expect(err).NotTo(HaveOccurred())
	return bom
}
