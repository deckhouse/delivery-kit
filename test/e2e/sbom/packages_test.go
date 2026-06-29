package e2e_build_test

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM os-pm packages", Label("e2e", "sbom", "packages", "simple"), func() {
	DescribeTable("verifies licenses, hashes, externalRefs, properties, and dependency graph on a single image",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_packages_deep"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-packages-deep-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)

			sbomtest.AssertHasLicense(bom, "demo-app", "9.9.9", "MIT")
			sbomtest.AssertHasLicense(bom, "demo-lib", "2.0.0", "MIT")

			sbomtest.AssertHasHash(bom, "demo-app", "9.9.9", cdx.HashAlgoSHA256,
				"1111111111111111111111111111111111111111111111111111111111111111")
			sbomtest.AssertHasHash(bom, "demo-lib", "2.0.0", cdx.HashAlgoSHA256,
				"2222222222222222222222222222222222222222222222222222222222222222")

			sbomtest.AssertHasExternalReference(bom, "demo-app", "9.9.9", cdx.ERTypeVCS,
				"https://example.com/demo-app")
			sbomtest.AssertHasExternalReference(bom, "demo-lib", "2.0.0", cdx.ERTypeVCS,
				"https://example.com/demo-lib")

			sbomtest.AssertHasProperty(bom, "demo-app", "9.9.9", "werf:pm:arch", "linux/amd64")
			sbomtest.AssertHasProperty(bom, "demo-app", "9.9.9", "werf:pm:type", "runtime")
			sbomtest.AssertHasProperty(bom, "demo-app", "9.9.9", "werf:pm:repo", "example/demo-app")
			sbomtest.AssertHasProperty(bom, "demo-lib", "2.0.0", "werf:pm:arch", "linux/amd64")

			sbomtest.AssertDependsOn(bom,
				"pkg:generic/demo-app@9.9.9?repository_url=https%3A%2F%2Fexample.com%2Fdemo-app",
				"pkg:generic/demo-lib@2.0.0?repository_url=https%3A%2F%2Fexample.com%2Fdemo-lib",
			)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("merges parent base-layer os-pm packages into child image SBOM",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_packages_base_merge"
			SuiteData.InitTestRepo(ctx, repoDirname, "packages_merge/base_with_child")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-packages-base-merge-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)

			sbomtest.AssertHasComponent(bom, "base-pkg", "1.0.0")
			sbomtest.AssertHasComponent(bom, "demo-app", "9.9.9")
			sbomtest.AssertHasComponent(bom, "demo-lib", "2.0.0")

			sbomtest.AssertHasLicense(bom, "base-pkg", "1.0.0", "MIT")
			sbomtest.AssertHasHash(bom, "base-pkg", "1.0.0", cdx.HashAlgoSHA256,
				"3333333333333333333333333333333333333333333333333333333333333333")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("propagates parent fromImage os-pm packages into child image SBOM (no own packages)",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_packages_parent_propagation"
			SuiteData.InitTestRepo(ctx, repoDirname, "packages_merge/parent_propagation")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-packages-parent-propagation-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			sbomtest.AssertHasComponent(bom, "demo-app", "9.9.9")
			sbomtest.AssertHasComponent(bom, "demo-lib", "2.0.0")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("build fails when pm script returns invalid (non-JSON) output",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_packages_broken_pm"
			SuiteData.InitTestRepo(ctx, repoDirname, "negative/broken_pm")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-packages-broken-pm-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			out := werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					Envs:       builderEnv,
				},
			})
			Expect(out).To(SatisfyAny(
				ContainSubstring("parse pm info"),
				ContainSubstring("collect os-pm SBOM"),
			), "expected pm-info parse failure; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("build fails when pm binary is missing in the image despite os-pm packages declared",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_packages_no_pm_binary"
			SuiteData.InitTestRepo(ctx, repoDirname, "negative/no_pm_binary")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-packages-no-pm-binary-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			out := werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					Envs:       builderEnv,
				},
			})
			Expect(out).To(SatisfyAll(
				ContainSubstring("Code: 127"),
				SatisfyAny(
					ContainSubstring("pm: not found"),
					ContainSubstring("pm: command not found"),
				),
			), "expected shell exit 127 with pm-binary-missing diagnostic; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
