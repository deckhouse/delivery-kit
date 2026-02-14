package e2e_build_test

import (
	"archive/tar"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	imagePkg "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/extract"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
	"github.com/werf/werf/v2/test/pkg/contback"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("Simple build", Label("e2e", "build", "sbom", "simple"), func() {
	DescribeTable("should generate and store SBOM as an image",
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
						sbomImgInspect := contRuntime.GetImageInspect(ctx, sbomImage.ImageName(reportRecord.DockerImageName))

						// shared labels
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfVersionLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfVersionLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfProjectRepoCommitLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfProjectRepoCommitLabel]))
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfStageContentDigestLabel]).To(Equal(imgInspect.Config.Labels[imagePkg.WerfStageContentDigestLabel]))
						// sbom labels
						Expect(sbomImgInspect.Config.Labels[imagePkg.WerfSbomLabel]).To(Equal("0c15bc4e5bd8541138b5b6b7065eb8f641284b4913878d953be46419f50e8ebc"))

						By("state0: SBOM image file system layout")
						opener := func() (io.ReadCloser, error) {
							return contRuntime.SaveImageToStream(ctx, sbomImage.ImageName(reportRecord.DockerImageName)), nil
						}

						flattenedFsStreamReaderCloser, err := extract.FromImageStream(opener)
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
							"sbom/cyclonedx@1.6/f2b172aa9b952cfba7ae9914e7e5a9760ff0d2c7d5da69d09195c63a2577da79.json",
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
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
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

	DescribeTable("should succeed when base image SBOM is scratch",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo_base_sbom"
			fixtureRelPath := "sbom/state1"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, _ := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_base_sbom.json"), nil)

			Expect(buildOut).To(ContainSubstring("SBOM processing"))
			Expect(buildOut).To(ContainSubstring("image stapel"))
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
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)

	DescribeTable("should fail when base image SBOM is not found in registry",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo_base_sbom"
			fixtureRelPath := "sbom/state2"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			By("building images (expecting failure)")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			out, err := werfProject.BuildWithErr(ctx, nil)

			Expect(err).To(HaveOccurred(), "build should fail when base image SBOM is not found")
			Expect(out).To(ContainSubstring("unable to get base image"))
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
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)

	DescribeTable("should succeed and store SBOMs",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirName := "repo_import_sbom"
			fixtureRelPath := "sbom/import_stapel/state0"
			SuiteData.InitTestRepo(ctx, repoDirName, fixtureRelPath)

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirName))
			_ = werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"stapel-scratch-based"},
				},
			})

			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, _ := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_import_sbom.json"), nil)

			Expect(buildOut).To(ContainSubstring("SBOM processing"))
			Expect(buildOut).To(ContainSubstring("image stapel-scratch-based"))
			Expect(buildOut).To(ContainSubstring("image stapel"))
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
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)

	DescribeTable("should fail when import image not found and store SBOMs",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirName := "repo_import_sbom"
			fixtureRelPath := "sbom/import_stapel/state0"
			SuiteData.InitTestRepo(ctx, repoDirName, fixtureRelPath)

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirName))
			out, err := werfProject.BuildWithErr(ctx, nil)

			Expect(err).To(HaveOccurred(), "build should fail when base image SBOM is not found")
			Expect(out).To(ContainSubstring("not found in container registry"))
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
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)
})

var _ = Describe("SBOM merge", Label("e2e", "build", "sbom", "merge", "simple"), func() {
	DescribeTable("should merge base image SBOM with fragment",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			contRuntime, err := contback.NewContainerBackend(testOpts.ContainerBackendMode)
			if err == contback.ErrRuntimeUnavailable {
				Skip(err.Error())
			} else if err != nil {
				Fail(err.Error())
			}

			By("preparing test repo")
			repoDirname := "repo_merge_base_fragment"
			fixtureRelPath := "sbom/merge_base_fragment"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_merge_base_fragment.json"), nil)

			Expect(buildOut).To(ContainSubstring("SBOM processing"))

			By("extracting and verifying merged SBOM")
			for imgName, reportRecord := range buildReport.Images {
				if imgName != "app" {
					continue
				}

				bom := extractBOMFromSbomImage(ctx, contRuntime, reportRecord.DockerImageName)

				By("verifying SBOM structure")
				Expect(bom.BOMFormat).To(Equal("CycloneDX"))
				Expect(bom.SpecVersion).To(Equal(cdx.SpecVersion1_6))
				Expect(bom.Version).To(Equal(1))
				Expect(bom.SerialNumber).To(HavePrefix("urn:uuid:"))
				Expect(bom.Components).NotTo(BeNil())

				By("verifying fragment component is present")
				components := *bom.Components
				Expect(findComponentByName(components, "custom-component")).NotTo(BeNil(),
					"fragment component 'custom-component' should be present in merged SBOM")

				By("verifying components count (fragment only, scratch has no components)")
				Expect(len(components)).To(BeNumerically(">=", 1),
					"merged SBOM should contain at least fragment component")

				By("verifying Services are merged")
				if bom.Services != nil {
					services := *bom.Services
					Expect(findServiceByName(services, "custom-api-service")).NotTo(BeNil(),
						"fragment service 'custom-api-service' should be present")
					Expect(len(services)).To(BeNumerically(">=", 1))
				}

				By("verifying ExternalReferences are merged")
				if bom.ExternalReferences != nil {
					refs := *bom.ExternalReferences
					Expect(findExternalReferenceByURL(refs, "https://example.com")).NotTo(BeNil(),
						"fragment external reference should be present")
					Expect(findExternalReferenceByURL(refs, "https://docs.example.com")).NotTo(BeNil(),
						"fragment documentation reference should be present")
					Expect(len(refs)).To(BeNumerically(">=", 2))
				}

				By("verifying Properties are merged")
				if bom.Properties != nil {
					props := *bom.Properties
					Expect(findPropertyByName(props, "build-environment")).NotTo(BeNil(),
						"fragment property 'build-environment' should be present")
					Expect(findPropertyByName(props, "custom-property")).NotTo(BeNil(),
						"fragment property 'custom-property' should be present")
					Expect(len(props)).To(BeNumerically(">=", 2))
				}

				By("verifying Annotations are merged")
				if bom.Annotations != nil {
					annotations := *bom.Annotations
					Expect(findAnnotationByText(annotations, "This is a test annotation for merge verification")).NotTo(BeNil(),
						"fragment annotation should be present")
					Expect(len(annotations)).To(BeNumerically(">=", 1))
				}
			}
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
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)

	DescribeTable("should merge all SBOM sources (base + import + fragment)",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			contRuntime, err := contback.NewContainerBackend(testOpts.ContainerBackendMode)
			if err == contback.ErrRuntimeUnavailable {
				Skip(err.Error())
			} else if err != nil {
				Fail(err.Error())
			}

			By("preparing test repo")
			repoDirname := "repo_merge_full"
			fixtureRelPath := "sbom/merge_full"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))
			_ = werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"builder"},
				},
			})

			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report_merge_full.json"), nil)

			Expect(buildOut).To(ContainSubstring("SBOM processing"))

			By("extracting and verifying merged SBOM for app image")
			for imgName, reportRecord := range buildReport.Images {
				if imgName != "app" {
					continue
				}

				bom := extractBOMFromSbomImage(ctx, contRuntime, reportRecord.DockerImageName)

				By("verifying SBOM structure")
				Expect(bom.BOMFormat).To(Equal("CycloneDX"))
				Expect(bom.SpecVersion).To(Equal(cdx.SpecVersion1_6))
				Expect(bom.Components).NotTo(BeNil())

				components := *bom.Components

				By("verifying app custom component from fragment is present")
				Expect(findComponentByName(components, "app-custom")).NotTo(BeNil(),
					"app-custom component from fragment should be present")

				By("verifying builder custom component from import is present")
				Expect(findComponentByName(components, "builder-custom")).NotTo(BeNil(),
					"builder-custom component from imported image should be present")

				By("verifying merged SBOM contains components from import and fragment")
				Expect(len(components)).To(BeNumerically(">=", 2),
					"merged SBOM should contain components from import and fragment")

				By("verifying metadata is present")
				Expect(bom.Metadata).NotTo(BeNil())

				By("verifying Services from both builder and app are merged")
				if bom.Services != nil {
					services := *bom.Services

					Expect(findServiceByName(services, "builder-service")).NotTo(BeNil(),
						"builder service should be present from import")

					Expect(findServiceByName(services, "app-api-service")).NotTo(BeNil(),
						"app service should be present from fragment")

					Expect(len(services)).To(BeNumerically(">=", 2),
						"should contain services from both builder and app")
				}

				By("verifying Properties from both sources are merged")
				if bom.Properties != nil {
					props := *bom.Properties

					Expect(findPropertyByName(props, "builder-property")).NotTo(BeNil(),
						"builder property should be present from import")

					Expect(findPropertyByName(props, "app-property")).NotTo(BeNil(),
						"app property should be present from fragment")

					Expect(len(props)).To(BeNumerically(">=", 2),
						"should contain properties from both sources")
				}

				By("verifying ExternalReferences are merged")
				if bom.ExternalReferences != nil {
					refs := *bom.ExternalReferences

					Expect(findExternalReferenceByURL(refs, "https://github.com/example/app")).NotTo(BeNil(),
						"app external reference should be present")
				}

				By("verifying Annotations are merged")
				if bom.Annotations != nil {
					annotations := *bom.Annotations

					Expect(findAnnotationByText(annotations, "Application level annotation")).NotTo(BeNil(),
						"app annotation should be present")
				}
			}
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
		Entry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)
})

func extractBOMFromSbomImage(ctx SpecContext, contRuntime contback.ContainerBackend, dockerImageName string) *cdx.BOM {
	sbomImageName := sbomImage.ImageName(dockerImageName)

	opener := func() (io.ReadCloser, error) {
		return contRuntime.SaveImageToStream(ctx, sbomImageName), nil
	}

	artifactContent, err := extract.FromImageBytes(opener)
	Expect(err).NotTo(HaveOccurred(), "failed to find SBOM artifact")

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(artifactContent)
	Expect(err).NotTo(HaveOccurred(), "failed to parse SBOM artifact")

	return bom
}

func findComponentByName(components []cdx.Component, name string) *cdx.Component {
	for i := range components {
		if components[i].Name == name {
			return &components[i]
		}
	}
	return nil
}

func findServiceByName(services []cdx.Service, name string) *cdx.Service {
	for i := range services {
		if services[i].Name == name {
			return &services[i]
		}
	}
	return nil
}

func findPropertyByName(properties []cdx.Property, name string) *cdx.Property {
	for i := range properties {
		if properties[i].Name == name {
			return &properties[i]
		}
	}
	return nil
}

func findExternalReferenceByURL(refs []cdx.ExternalReference, url string) *cdx.ExternalReference {
	for i := range refs {
		if refs[i].URL == url {
			return &refs[i]
		}
	}
	return nil
}

func findAnnotationByText(annotations []cdx.Annotation, text string) *cdx.Annotation {
	for i := range annotations {
		if annotations[i].Text == text {
			return &annotations[i]
		}
	}
	return nil
}
