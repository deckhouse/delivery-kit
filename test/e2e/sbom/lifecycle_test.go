package e2e_build_test

import (
	"encoding/json"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v3/test/pkg/externalrefmock"
	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM lifecycle", Label("e2e", "sbom", "lifecycle", "simple"), func() {
	It("single-image pipeline: build → get → parse SBOM content", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_lifecycle_single"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		sbomtest.AssertHasComponent(bom, "curl", "8.12.1")
		sbomtest.AssertHasComponent(bom, "openssl", "3.6.2")
	})

	DescribeTable("multi-image: build + merge two image SBOMs into a product SBOM",
		Label("annotation-consistency"),
		func(ctx SpecContext, isprasFormat string) {
			setupSbomBuildEnv()

			repoDirname := "repo_sbom_lifecycle_multi_" + isprasFormat
			SuiteData.InitTestRepo(ctx, repoDirname, "lifecycle/multi_image")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("lifecycle_multi_"+isprasFormat+".json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{}},
			)

			mapping := map[string]string{}
			imageBOMs := map[string]*cdx.BOM{}
			for name, rec := range buildReport.Images {
				Expect(rec.DockerImageDigest).NotTo(BeEmpty(),
					"image %q has no digest in build report", name)
				mapping[name] = rec.DockerImageDigest
				imageBOMs[name] = sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
					CommonOptions: werf.CommonOptions{ExtraArgs: []string{name}},
				}))
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
				},
			})

			merged := sbomtest.MustParseSBOMOutput(mergeOut)
			sbomtest.AssertHasComponent(merged, "jq", "1.8.1")
			sbomtest.AssertHasComponent(merged, "yq", "4.53.6")

			sbomtest.AssertHasLicense(merged, "jq", "1.8.1", "MIT")
			sbomtest.AssertHasLicense(merged, "yq", "4.53.6", "MIT")
			sbomtest.AssertHasHash(merged, "jq", "1.8.1", cdx.HashAlgoSHA256,
				"99f0d20ba2e7084999a592d6db575ff3b734c960f9b9f61fee88f0e2e4430164")
			sbomtest.AssertHasHash(merged, "yq", "4.53.6", cdx.HashAlgoSHA256,
				"a5e7736e6248f0068b4a258876ba54ef4e251f6357e1654bfb541bd2d09766e0")

			// GOST properties from build.sbom.gost must be preserved through merge on every component.
			// NOTE: metadata.component of a merged BOM is a synthetic product identity from --app-name
			// and does NOT carry GOST — hence AssertGostPropertyOnComponents (not AssertGostProperty).
			sbomtest.AssertGostPropertyOnComponents(merged, gost.PropertyAttackSurface, gost.GostValueYes)
			sbomtest.AssertGostPropertyOnComponents(merged, gost.PropertySecurityFunction, gost.GostValueYes)

			depRefPrefix := lo.Ternary(isprasFormat == "container", "backend/", "")
			sbomtest.AssertDependsOn(merged,
				depRefPrefix+"pkg:generic/curl@8.12.1?containerfactoryversion=v3.0.2",
				depRefPrefix+"pkg:generic/openssl@3.6.2?containerfactoryversion=v3.0.2")
			sbomtest.AssertDependencyGraphResolves(merged)
			for name, imageBOM := range imageBOMs {
				rootRef := imageBOM.Metadata.Component.BOMRef
				sbomtest.AssertKeepsDependencyEdges(merged, imageBOM, func(ref string) string {
					if ref == rootRef {
						return lo.Ternary(isprasFormat == "container", name, "")
					}
					return lo.Ternary(isprasFormat == "container", name+"/"+ref, ref)
				})
			}
		},
		Entry("container format", "container"),
		Entry("oss format", "oss"),
	)

	DescribeTable("single-image full lifecycle: build → merge → validate produces ISPRAS-valid SBOM",
		func(ctx SpecContext, isprasFormat string) {
			setupSbomBuildEnv()

			repoDirname := "repo_sbom_lifecycle_validate_" + isprasFormat
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("lifecycle_validate_"+isprasFormat+".json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{}},
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
				},
			})

			validateOut := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--path", mergedJSONPath, "--ispras-format", isprasFormat},
				},
			})
			Expect(validateOut).To(ContainSubstring("OK"),
				"merged SBOM did not pass %q validation; output:\n%s", isprasFormat, validateOut)
		},
		Entry("container format", "container"),
		// The SBOM attached to the base-images v3.0.2 builders was generated by a
		// delivery-kit that still ran syft over the whole stapel image, so it carries
		// syft's os-release `operating-system` component without a vcs reference,
		// which the ISPRAS oss schema rejects. Re-enable once base-images is rebuilt
		// with a delivery-kit that no longer scans stapel images and the digests are
		// re-pinned.
		XEntry("oss format", "oss"),
	)

	It("source distributions: build → merge → validate keeps the STREEBOG digest", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_lifecycle_src_dist"
		SuiteData.InitTestRepo(ctx, repoDirname, "lifecycle/source_distribution")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)
		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("lifecycle_src_dist.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{}},
		)

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		// The resolver answers an npm purl with the published archive, so lodash
		// carries a source distribution as its only link — the case the ISPRAS
		// schema requires a digest for.
		lodashArchive := externalrefmock.SourceDistributionURL("pkg:npm/lodash@4.17.21")
		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		assertSourceDistributionDigest(bom, "lodash", "4.17.21", lodashArchive)

		mapping := map[string]string{}
		for name, rec := range buildReport.Images {
			mapping[name] = rec.DockerImageDigest
		}
		Expect(mapping).To(HaveLen(1), "expected exactly 1 image in build report")

		mappingPath := filepath.Join(SuiteData.TmpDir, "lifecycle_src_dist_mapping.json")
		writeMappingFile(mappingPath, mapping)

		mergedJSONPath := filepath.Join(SuiteData.TmpDir, "lifecycle_src_dist_merged.json")
		mergeOut := werfProject.SbomMerge(ctx, &werf.SbomMergeOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--input", mappingPath,
					"--ispras-format", "oss",
					"--app-name", "lifecycle-src-dist",
					"--app-version", "1.0.0",
					"--manufacturer", "e2e-test",
					"--output", mergedJSONPath,
				},
			},
		})
		Expect(mergeOut).NotTo(BeEmpty())

		mergedJSON, err := os.ReadFile(mergedJSONPath)
		Expect(err).NotTo(HaveOccurred())
		merged := &cdx.BOM{}
		Expect(json.Unmarshal(mergedJSON, merged)).To(Succeed())
		assertSourceDistributionDigest(merged, "lodash", "4.17.21", lodashArchive)

		// The merged document is not run through "sbom validate --ispras-format oss"
		// here for the reason the oss entry of the table above is disabled: the SBOM
		// of the base-images builder carries a component with neither a vcs nor a
		// source-distribution link, and the oss schema rejects it before it gets to
		// any digest. That the schema accepts the shape asserted above is covered by
		// the "valid OSS with a source distribution digest" fixture in
		// test/e2e/sbom-validate.
	})

	It("sbom get fails when SBOM is not enabled in werf.yaml", func(ctx SpecContext) {
		setupSbomBuildEnv()

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
	})

	It("sbom merge fails when --input file does not exist", func(ctx SpecContext) {
		setupSbomBuildEnv()

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
	})

	It("sbom merge fails when --input contains malformed JSON", func(ctx SpecContext) {
		setupSbomBuildEnv()

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
	})

	It("sbom merge fails when --ispras-format is invalid", func(ctx SpecContext) {
		setupSbomBuildEnv()

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
	})

	It("sbom merge fails when a required flag is missing", func(ctx SpecContext) {
		setupSbomBuildEnv()

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
	})
})

// assertSourceDistributionDigest checks the shape the ISPRAS oss schema demands
// of a leaf component whose only link is a source distribution: the archive URL
// and a STREEBOG digest of it, both carried by the same reference.
func assertSourceDistributionDigest(bom *cdx.BOM, name, version, archiveURL string) {
	comp := sbomtest.FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(), "component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.ExternalReferences).NotTo(BeNil(),
		"component %s@%s has no external references", name, version)

	// A vcs link next to it would take the component out of the schema branch
	// that demands the digest, and the assertions below would prove nothing.
	ExpectWithOffset(1, *comp.ExternalReferences).NotTo(ContainElement(HaveField("Type", cdx.ERTypeVCS)),
		"component %s@%s also carries a vcs link, the digest requirement would not apply", name, version)

	refs := lo.Filter(*comp.ExternalReferences, func(ref cdx.ExternalReference, _ int) bool {
		return ref.Type == cdx.ERTypeSourceDistribution
	})
	ExpectWithOffset(1, refs).To(HaveLen(1),
		"component %s@%s: expected exactly one source distribution, got %v", name, version, *comp.ExternalReferences)
	ExpectWithOffset(1, refs[0].URL).To(Equal(archiveURL))
	ExpectWithOffset(1, refs[0].Hashes).NotTo(BeNil(),
		"component %s@%s: source distribution %s carries no digest", name, version, refs[0].URL)
	ExpectWithOffset(1, *refs[0].Hashes).To(ContainElement(cdx.Hash{
		Algorithm: cdx.HashAlgorithm(externalrefmock.SourceDistributionHash.Algorithm),
		Value:     externalrefmock.SourceDistributionHash.Content,
	}))
}

func writeMappingFile(path string, mapping map[string]string) {
	data, err := json.Marshal(mapping)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, os.WriteFile(path, data, 0o644)).To(Succeed())
}
