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

			By("state0: initial build with [demo-app] only")
			out0 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out0).To(ContainSubstring(sbomRegenMarker), "expected initial SBOM generation")

			bom0 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom0, "demo-app", "9.9.9")
			sbomtest.AssertNoComponent(bom0, "demo-lib")

			By("rebuild state0 without changes: SBOM must come from cache")
			outCached := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(outCached).To(ContainSubstring(sbomCachedMarker),
				"expected cached SBOM marker %q, output was:\n%s", sbomCachedMarker, outCached)

			By("state1: add demo-lib to packages spec → SBOM must regenerate")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "stage_deps/state1")
			out1 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out1).To(ContainSubstring(sbomRegenMarker),
				"expected SBOM regeneration after adding package")

			bom1 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom1, "demo-app", "9.9.9")
			sbomtest.AssertHasComponent(bom1, "demo-lib", "2.0.0")

			By("state2: remove demo-lib AND bump demo-app version → SBOM must regenerate")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "stage_deps/state2")
			out2 := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			Expect(out2).To(ContainSubstring(sbomRegenMarker),
				"expected SBOM regeneration after removing package + version bump")

			bom2 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom2, "demo-app", "10.0.0")
			sbomtest.AssertNoComponent(bom2, "demo-lib")
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
			sbomtest.AssertHasComponent(bom0, "demo-app", "9.9.9")

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
			sbomtest.AssertHasComponent(bom1, "demo-app", "9.9.9")
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

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-type-change-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			By("state0: os-pm — SBOM contains generic PURL")
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			bom0 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertHasComponent(bom0, "demo-app", "9.9.9")
			sbomtest.AssertHasPURL(bom0, "pkg:generic/demo-app@9.9.9?repository_url=https%3A%2F%2Fexample.com%2Fdemo-app")

			By("state1: go-mod — SBOM contains golang PURL, no generic pkg")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "type_change/state1")
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "tag", "v1.0.0")

			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})
			bom1 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}, Envs: builderEnv},
			}))
			sbomtest.AssertNoComponent(bom1, "demo-app")
			sbomtest.AssertHasComponent(bom1, "example.com/mylib", "v1.0.0")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
