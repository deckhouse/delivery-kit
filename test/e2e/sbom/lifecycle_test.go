package e2e_build_test

import (
	"encoding/json"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v2/test/pkg/report"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM lifecycle", Label("e2e", "sbom", "lifecycle", "simple"), func() {
	DescribeTable("single-image pipeline: build → get → parse SBOM content",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_lifecycle_single"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-lifecycle-single-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			sbomtest.AssertHasComponent(bom, "curl", "8.12.1")
			sbomtest.AssertHasComponent(bom, "openssl", "3.6.2")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("multi-image: build + merge two image SBOMs into a product SBOM",
		Label("annotation-consistency"),
		func(ctx SpecContext, testOpts sbomTestOptions, isprasFormat string) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_lifecycle_multi_" + isprasFormat
			SuiteData.InitTestRepo(ctx, repoDirname, "lifecycle/multi_image")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-lifecycle-multi-builder-"+isprasFormat)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("lifecycle_multi_"+isprasFormat+".json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			mapping := map[string]string{}
			for name, rec := range buildReport.Images {
				Expect(rec.DockerImageDigest).NotTo(BeEmpty(),
					"image %q has no digest in build report", name)
				mapping[name] = rec.DockerImageDigest
			}
			Expect(mapping).To(HaveLen(2), "expected exactly 2 images in build report")

			mappingPath := filepath.Join(SuiteData.TmpDir, "lifecycle_multi_mapping_"+isprasFormat+".json")
			writeMappingFile(mappingPath, mapping)

			mergeOut := werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--input", mappingPath,
						"--ispras-format", isprasFormat,
						"--app-name", "lifecycle-product",
						"--app-version", "1.0.0",
						"--manufacturer", "e2e-test",
					},
					Envs: builderEnv,
				},
			})

			merged := sbomtest.MustParseSBOMOutput(mergeOut)
			sbomtest.AssertHasComponent(merged, "jq", "1.8.1")
			sbomtest.AssertHasComponent(merged, "yq", "4.48.1")

			sbomtest.AssertHasLicense(merged, "jq", "1.8.1", "MIT")
			sbomtest.AssertHasLicense(merged, "yq", "4.48.1", "MIT")
			sbomtest.AssertHasHash(merged, "jq", "1.8.1", cdx.HashAlgoSHA256,
				"c8336383b9a8de6393af6254acd305823a3db4dbb091a7ea865bbbf95e8cc899")
			sbomtest.AssertHasHash(merged, "yq", "4.48.1", cdx.HashAlgoSHA256,
				"2ce3f5219fb99420eb3396da2d6d6f13e75e5f5ed0abcf038db17c2920ec426c")

			// GOST properties from build.sbom.gost must be preserved through merge on every component.
			// NOTE: metadata.component of a merged BOM is a synthetic product identity from --app-name
			// and does NOT carry GOST — hence AssertGostPropertyOnComponents (not AssertGostProperty).
			sbomtest.AssertGostPropertyOnComponents(merged, gost.PropertyAttackSurface, gost.GostValueYes)
			sbomtest.AssertGostPropertyOnComponents(merged, gost.PropertySecurityFunction, gost.GostValueYes)
		},
		Entry("container format using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, "container"),
		Entry("container format using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}, "container"),
		Entry("oss format using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, "oss"),
		Entry("oss format using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}, "oss"),
		XEntry("container format using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}, "container"),
		XEntry("container format using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}, "container"),
	)

	DescribeTable("single-image full lifecycle: build → merge → validate produces ISPRAS-valid SBOM",
		func(ctx SpecContext, testOpts sbomTestOptions, isprasFormat string) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_lifecycle_validate_" + isprasFormat
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-lifecycle-validate-builder-"+isprasFormat)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("lifecycle_validate_"+isprasFormat+".json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			mapping := map[string]string{}
			for name, rec := range buildReport.Images {
				mapping[name] = rec.DockerImageDigest
			}
			Expect(mapping).To(HaveLen(1), "expected exactly 1 image in build report")

			mappingPath := filepath.Join(SuiteData.TmpDir, "lifecycle_validate_mapping_"+isprasFormat+".json")
			writeMappingFile(mappingPath, mapping)

			mergedJSONPath := filepath.Join(SuiteData.TmpDir, "lifecycle_validate_merged_"+isprasFormat+".json")
			werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--input", mappingPath,
						"--ispras-format", isprasFormat,
						"--app-name", "lifecycle-app",
						"--app-version", "1.0.0",
						"--manufacturer", "e2e-test",
						"--output", mergedJSONPath,
					},
					Envs: builderEnv,
				},
			})

			validateOut := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--path", mergedJSONPath, "--ispras-format", isprasFormat},
					Envs:      builderEnv,
				},
			})
			Expect(validateOut).To(ContainSubstring("OK"),
				"merged SBOM did not pass %q validation; output:\n%s", isprasFormat, validateOut)
		},
		Entry("container format using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, "container"),
		Entry("container format using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}, "container"),
		XEntry("container format using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}, "container"),
		XEntry("container format using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}, "container"),
	)

	DescribeTable("sbom get fails when SBOM is not enabled in werf.yaml",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_lifecycle_get_disabled"
			SuiteData.InitTestRepo(ctx, repoDirname, "negative/sbom_disabled")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			out := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					ExtraArgs:  []string{"app"},
				},
			})
			Expect(out).To(ContainSubstring("SBOM should be enabled"),
				"expected explicit error about disabled SBOM; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("sbom merge fails when --input file does not exist",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out := werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					ExtraArgs: []string{
						"--input", "/nonexistent/mapping.json",
						"--ispras-format", "container",
						"--app-name", "test-product",
						"--app-version", "1.0.0",
						"--manufacturer", "test",
					},
				},
			})
			Expect(out).To(ContainSubstring("unable to read"),
				"expected error about unreadable input file; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)

	DescribeTable("sbom merge fails when --input contains malformed JSON",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			mappingPath := filepath.Join(SuiteData.TmpDir, "malformed_mapping.json")
			Expect(os.WriteFile(mappingPath, []byte("{not-valid-json"), 0o644)).To(Succeed())

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out := werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					ExtraArgs: []string{
						"--input", mappingPath,
						"--ispras-format", "container",
						"--app-name", "test-product",
						"--app-version", "1.0.0",
						"--manufacturer", "test",
					},
				},
			})
			Expect(out).To(ContainSubstring("unable to parse JSON"),
				"expected JSON parse error; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)

	DescribeTable("sbom merge fails when --ispras-format is invalid",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			// Create a syntactically valid mapping so validation reaches --ispras-format check.
			mappingPath := filepath.Join(SuiteData.TmpDir, "valid_mapping_for_format_check.json")
			writeMappingFile(mappingPath, map[string]string{
				"app": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			})

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out := werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					ExtraArgs: []string{
						"--input", mappingPath,
						"--ispras-format", "invalid-format",
						"--app-name", "test-product",
						"--app-version", "1.0.0",
						"--manufacturer", "test",
					},
				},
			})
			Expect(out).To(ContainSubstring("ispras-format"),
				"expected error mentioning ispras-format; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)

	DescribeTable("sbom merge fails when a required flag is missing",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			mappingPath := filepath.Join(SuiteData.TmpDir, "valid_mapping_for_flag_check.json")
			writeMappingFile(mappingPath, map[string]string{
				"app": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			})

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out := werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					ExtraArgs: []string{
						"--input", mappingPath,
						"--ispras-format", "container",
						// --app-name intentionally omitted
						"--app-version", "1.0.0",
						"--manufacturer", "test",
					},
				},
			})
			Expect(out).To(ContainSubstring("--app-name"),
				"expected error mentioning missing --app-name flag; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)
})

func writeMappingFile(path string, mapping map[string]string) {
	data, err := json.Marshal(mapping)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, os.WriteFile(path, data, 0o644)).To(Succeed())
}
