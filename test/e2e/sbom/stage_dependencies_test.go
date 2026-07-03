package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM stageDependencies cache invalidation", Label("e2e", "sbom", "stage-deps", "simple"), func() {
	const sbomCachedMarker = "Use previously generated SBOM from registry"
	const sbomRegenMarker = "SBOM processing"

	DescribeTable("regenerates SBOM on package spec changes; uses cache when unchanged",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_stage_deps"
			SuiteData.InitTestRepo(ctx, repoDirname, "stage_deps/state0")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-stage-deps-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			By("state0: initial build with [jq] only")
			out0 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out0).To(ContainSubstring(sbomRegenMarker), "expected initial SBOM generation")

			bom0 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom0, "jq", "1.8.1")
			sbomtest.AssertNoComponent(bom0, "tini")
			sbomtest.AssertNoComponent(bom0, "yq")

			By("rebuild state0 without changes: SBOM must come from cache")
			outCached := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(outCached).To(ContainSubstring(sbomCachedMarker),
				"expected cached SBOM marker %q, output was:\n%s", sbomCachedMarker, outCached)

			By("state1: add tini to packages spec → SBOM must regenerate")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "stage_deps/state1")
			out1 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out1).To(ContainSubstring(sbomRegenMarker),
				"expected SBOM regeneration after adding package")

			bom1 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom1, "jq", "1.8.1")
			sbomtest.AssertHasComponent(bom1, "tini", "0.19.0")

			By("state2: swap tini → yq (remove tini, add yq) → SBOM must regenerate")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "stage_deps/state2")
			out2 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out2).To(ContainSubstring(sbomRegenMarker),
				"expected SBOM regeneration after swapping package spec")

			bom2 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom2, "jq", "1.8.1")
			sbomtest.AssertHasComponent(bom2, "yq", "4.48.1")
			sbomtest.AssertNoComponent(bom2, "tini")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("changes to a file listed in git.stageDependencies.packages invalidate the SBOM cache",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_stage_deps_file"
			SuiteData.InitTestRepo(ctx, repoDirname, "stage_deps_file/state0")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-stage-deps-file-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			By("state0: initial build → SBOM generated")
			out0 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out0).To(ContainSubstring(sbomRegenMarker), "expected initial SBOM generation")

			bom0 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom0, "jq", "1.8.1")

			By("rebuild without changes → SBOM cache hit")
			outCached := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(outCached).To(ContainSubstring(sbomCachedMarker),
				"expected cache hit on unchanged build; output:\n%s", outCached)

			By("state1: bump versions.txt → Packages stage invalidates → SBOM must regenerate")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "stage_deps_file/state1")
			out1 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out1).To(ContainSubstring(sbomRegenMarker),
				"expected SBOM regen after file tracked by stageDependencies.packages changed; output:\n%s", out1)

			bom1 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom1, "jq", "1.8.1")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("switching packages type from os-pm to go-mod regenerates SBOM with new scanner output",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_type_change"
			SuiteData.InitTestRepo(ctx, repoDirname, "type_change/state0")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv0 := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-type-change-builder-state0")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			By("state0: os-pm — SBOM contains real pm package (jq) with generic PURL")
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv0}})
			bom0 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv0},
			}))
			sbomtest.AssertHasComponent(bom0, "jq", "1.8.1")

			By("state1: go-mod — SBOM contains golang PURL, no os-pm pkg")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "type_change/state1")
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "tag", "v1.0.0")

			builderEnv1 := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-type-change-builder-state1")

			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv1}})
			bom1 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv1},
			}))
			sbomtest.AssertNoComponent(bom1, "jq")
			sbomtest.AssertHasComponent(bom1, "example.com/mylib", "v1.0.0")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
