package e2e_build_test

import (
	"archive/tar"
	"fmt"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	imagePkg "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/contback"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("Simple build", Label("e2e", "build", "sbom", "simple"), func() {
	DescribeTable("should generate and store SBOM as an image for stapel syntax",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			contRuntime, err := contback.NewContainerBackend(testOpts.ContainerBackendMode)
			if err == contback.ErrRuntimeUnavailable {
				Skip(err.Error())
			} else if err != nil {
				Fail(err.Error())
			}

			By("state0: case", func() {
				repoDirname := "repo0"
				fixtureRelPath := "sbom/state0"
				buildReportName := "report0.json"

				By("state0: preparing test repo")
				SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

				By("state0: building images")
				werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
				reportProject := report.NewProjectWithReport(werfProject)
				buildOut, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath(buildReportName), nil)
				Expect(buildOut).To(ContainSubstring("Building stage"))

				By("state0: SBOM logging output")
				Expect(buildOut).To(ContainSubstring("SBOM"))
				Expect(buildOut).To(ContainSubstring("Scan image"))
				Expect(buildOut).To(ContainSubstring("Build destination image"))

				for builtImgName, reportRecord := range buildReport.Images {
					By(fmt.Sprintf("state0: validate result for %q", builtImgName))
					{
						By("state0: SBOM image metadata")
						imgInspect := contRuntime.GetImageInspect(ctx, reportRecord.DockerImageName)
						sbomImgInspect := contRuntime.GetImageInspect(ctx, sbom.ImageName(reportRecord.DockerImageName))

						// shared labels
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfVersionLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfVersionLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfProjectRepoCommitLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfProjectRepoCommitLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfStageContentDigestLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfStageContentDigestLabel]))
						// sbom labels
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfSbomLabel]).To(Equal("f2b172aa9b952cfba7ae9914e7e5a9760ff0d2c7d5da69d09195c63a2577da79"))

						By("state0: SBOM image file system layout")
						opener := func() (io.ReadCloser, error) {
							return contRuntime.SaveImageToStream(ctx, sbom.ImageName(reportRecord.DockerImageName)), nil
						}

						flattenedFsStreamReaderCloser, err := sbom.ExtractFromImageStream(opener)
						Expect(err).To(Succeed(), "should extract SBOM image from the stream")

						var actualFilePaths []string
						err = utils.ForEachInTarball(tar.NewReader(flattenedFsStreamReaderCloser), func(header *tar.Header) error {
							actualFilePaths = append(actualFilePaths, header.Name)
							return nil
						})
						Expect(err).To(Succeed(), "should iterate over the tarball entries")
						Expect(flattenedFsStreamReaderCloser.Close()).To(Succeed(), "should close the stream reader")

						expectedFilePaths := []string{
							"sbom",
							"sbom/cyclonedx@1.6",
							"sbom/cyclonedx@1.6/70ee6b0600f471718988bc123475a625ecd4a5763059c62802ae6280e65f5623.json",
						}
						Expect(actualFilePaths).To(Equal(expectedFilePaths))
					}
				}
			})
		},
		Entry("without repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               false,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("without repo using BuildKit Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               false,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using BuildKit Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		// TODO (zaytsev): it does not work currently
		// https://github.com/werf/werf/actions/runs/15076648086/job/42385521980?pr=6860#step:11:150
		XEntry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		// TODO: "werf purge --project-name=..." is not implemented for Buildah. So we have potential risk to fail the test.
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}, FlakeAttempts(5)),
	)

	Describe("base image SBOM", Serial, Ordered, func() {
		DescribeTable("should succeed when base image SBOM is scratch",
			func(ctx SpecContext, testOpts baseImageSbomTestOptions) {
				By("initializing")
				setupEnv(testOpts.setupEnvOptions)

				By("preparing test repo")
				repoDirname := "repo_base_sbom_success"
				SuiteData.InitTestRepo(ctx, repoDirname, testOpts.FixtureRelPath)

				By("building images")
				werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
				reportProject := report.NewProjectWithReport(werfProject)
				buildOut, _ := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_base_sbom.json"), nil)

				Expect(buildOut).To(ContainSubstring("SBOM processing"))
			},
			Entry("stapel with local repo using Vanilla Docker", baseImageSbomTestOptions{
				setupEnvOptions: setupEnvOptions{
					ContainerBackendMode:        "vanilla-docker",
					WithLocalRepo:               true,
					WithStagedDockerfileBuilder: false,
				},
				FixtureRelPath: "sbom/state1",
			}),
			Entry("stapel with local repo using BuildKit Docker", baseImageSbomTestOptions{
				setupEnvOptions: setupEnvOptions{
					ContainerBackendMode:        "buildkit-docker",
					WithLocalRepo:               true,
					WithStagedDockerfileBuilder: false,
				},
				FixtureRelPath: "sbom/state1",
			}),
		)

		DescribeTable("should fail when base image SBOM is not found in registry",
			func(ctx SpecContext, testOpts baseImageSbomTestOptions) {
				By("initializing")
				setupEnv(testOpts.setupEnvOptions)

				contRuntime, err := contback.NewContainerBackend(testOpts.ContainerBackendMode)
				if err == contback.ErrRuntimeUnavailable {
					Skip(err.Error())
				} else if err != nil {
					Fail(err.Error())
				}

				By("ensuring local base image SBOM does not exist")
				contRuntime.RmImage(ctx, testOpts.BaseImageReference+"-sbom")

				By("preparing test repo")
				repoDirname := "repo_base_sbom"
				SuiteData.InitTestRepo(ctx, repoDirname, testOpts.FixtureRelPath)

				By("building images (expecting failure)")
				werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
				out, err := werfProject.BuildWithErr(ctx, nil)

				Expect(err).To(HaveOccurred(), "build should fail when base image SBOM is not found")
				Expect(out).To(ContainSubstring("not found in container registry"))
			},
			Entry("stapel with local repo using Vanilla Docker", baseImageSbomTestOptions{
				setupEnvOptions: setupEnvOptions{
					ContainerBackendMode:        "vanilla-docker",
					WithLocalRepo:               true,
					WithStagedDockerfileBuilder: false,
				},
				FixtureRelPath:     "sbom/state2",
				BaseImageReference: "registry.werf.io/werf/alpine:3.18",
			}),
			Entry("stapel with local repo using BuildKit Docker", baseImageSbomTestOptions{
				setupEnvOptions: setupEnvOptions{
					ContainerBackendMode:        "buildkit-docker",
					WithLocalRepo:               true,
					WithStagedDockerfileBuilder: false,
				},
				FixtureRelPath:     "sbom/state2",
				BaseImageReference: "registry.werf.io/werf/alpine:3.18",
			}),
		)

		DescribeTable("should succeed when child image uses base image built by werf",
			func(ctx SpecContext, testOpts baseImageSbomTestOptions) {
				By("initializing")
				setupEnv(testOpts.setupEnvOptions)

				contRuntime, err := contback.NewContainerBackend(testOpts.ContainerBackendMode)
				if err == contback.ErrRuntimeUnavailable {
					Skip(err.Error())
				} else if err != nil {
					Fail(err.Error())
				}

				By("preparing test repo")
				repoDirname := "repo_base_sbom_chain"
				SuiteData.InitTestRepo(ctx, repoDirname, testOpts.FixtureRelPath)

				By("building all images (base from scratch, child from base)")
				werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
				reportProject := report.NewProjectWithReport(werfProject)
				buildOut, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_chain.json"), nil)

				By("verifying build output")
				Expect(buildOut).To(ContainSubstring("SBOM processing"))

				By("verifying both images were built")
				Expect(buildReport.Images).To(HaveKey("base"))
				Expect(buildReport.Images).To(HaveKey("child"))

				for builtImgName, reportRecord := range buildReport.Images {
					By(fmt.Sprintf("validating SBOM for %q", builtImgName))
					{
						By(fmt.Sprintf("%s: verifying SBOM image exists", builtImgName))
						sbomImageName := sbom.ImageName(reportRecord.DockerImageName)
						sbomImgInspect := contRuntime.GetImageInspect(ctx, sbomImageName)
						Expect(sbomImgInspect).NotTo(BeNil(), "SBOM image should exist")

						By(fmt.Sprintf("%s: verifying image labels", builtImgName))
						imgInspect := contRuntime.GetImageInspect(ctx, reportRecord.DockerImageName)

						// shared labels between image and SBOM image
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfVersionLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfVersionLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfProjectRepoCommitLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfProjectRepoCommitLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfStageContentDigestLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfStageContentDigestLabel]))

						// SBOM-specific label should exist
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfSbomLabel]).NotTo(BeEmpty(), "SBOM label should be present")

						By(fmt.Sprintf("%s: verifying SBOM image filesystem", builtImgName))
						opener := func() (io.ReadCloser, error) {
							return contRuntime.SaveImageToStream(ctx, sbomImageName), nil
						}

						flattenedFsStreamReaderCloser, err := sbom.ExtractFromImageStream(opener)
						Expect(err).To(Succeed(), "should extract SBOM image from the stream")

						var actualFilePaths []string
						err = utils.ForEachInTarball(tar.NewReader(flattenedFsStreamReaderCloser), func(header *tar.Header) error {
							actualFilePaths = append(actualFilePaths, header.Name)
							return nil
						})
						Expect(err).To(Succeed(), "should iterate over the tarball entries")
						Expect(flattenedFsStreamReaderCloser.Close()).To(Succeed(), "should close the stream reader")

						// Verify SBOM filesystem structure
						Expect(actualFilePaths).To(ContainElement("sbom"))
						Expect(actualFilePaths).To(ContainElement("sbom/cyclonedx@1.6"))
						// Should have at least one JSON file in sbom/cyclonedx@1.6/
						hasJsonFile := false
						for _, path := range actualFilePaths {
							if len(path) > len("sbom/cyclonedx@1.6/") && path[:len("sbom/cyclonedx@1.6/")] == "sbom/cyclonedx@1.6/" {
								hasJsonFile = true
								break
							}
						}
						Expect(hasJsonFile).To(BeTrue(), "should have at least one SBOM JSON file")
					}
				}
			},
			Entry("stapel with local repo using Vanilla Docker", baseImageSbomTestOptions{
				setupEnvOptions: setupEnvOptions{
					ContainerBackendMode:        "vanilla-docker",
					WithLocalRepo:               true,
					WithStagedDockerfileBuilder: false,
				},
				FixtureRelPath: "sbom/state3",
			}),
			Entry("stapel with local repo using BuildKit Docker", baseImageSbomTestOptions{
				setupEnvOptions: setupEnvOptions{
					ContainerBackendMode:        "buildkit-docker",
					WithLocalRepo:               true,
					WithStagedDockerfileBuilder: false,
				},
				FixtureRelPath: "sbom/state3",
			}),
		)
	})
})

type baseImageSbomTestOptions struct {
	setupEnvOptions
	FixtureRelPath     string
	BaseImageReference string
}
