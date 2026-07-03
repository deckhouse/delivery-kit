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

			// curl is installed with its transitive dependencies (brotli, libc, libpsl, openssl, zstd).
			sbomtest.AssertHasLicense(bom, "curl", "8.12.1", "curl")
			sbomtest.AssertHasHash(bom, "curl", "8.12.1", cdx.HashAlgoSHA256,
				"4004dcee97992bf7fef837ee09e678f0f5c37e6bf892de141a2716ba890ce19a")
			// pm v1.1.11 uses a placeholder originalRepo for all packages; the real short-repo path
			// is exposed via the werf:pm:repo property instead.
			sbomtest.AssertHasExternalReference(bom, "curl", "8.12.1", cdx.ERTypeVCS,
				"https://github.com/example/repo")
			sbomtest.AssertHasProperty(bom, "curl", "8.12.1", "werf:pm:arch", "linux/amd64")
			sbomtest.AssertHasProperty(bom, "curl", "8.12.1", "werf:pm:type", "runtime")
			sbomtest.AssertHasProperty(bom, "curl", "8.12.1", "werf:pm:repo", "curl/curl")

			// transitive dependency openssl must be present with its own metadata.
			sbomtest.AssertHasComponent(bom, "openssl", "3.6.2")
			sbomtest.AssertHasLicense(bom, "openssl", "3.6.2", "Apache-2.0")
			sbomtest.AssertHasHash(bom, "openssl", "3.6.2", cdx.HashAlgoSHA256,
				"12d0999025b656e54caaad71eb6400be513e9e55c144d3e43896e8ce3012f54d")

			// dependency graph: curl depends on openssl. bom-ref uses lowercase qualifier key
			// containerfactoryversion (werf's cyclonedx serializer lowercases keys in bom-ref).
			sbomtest.AssertDependsOn(bom,
				"pkg:generic/curl@8.12.1?containerfactoryversion=v1.1.11",
				"pkg:generic/openssl@3.6.2?containerfactoryversion=v1.1.11",
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

			// child app's SBOM must contain the base-layer's jq plus its own curl.
			sbomtest.AssertHasComponent(bom, "jq", "1.8.1")
			sbomtest.AssertHasComponent(bom, "curl", "8.12.1")

			sbomtest.AssertHasLicense(bom, "jq", "1.8.1", "MIT")
			sbomtest.AssertHasHash(bom, "jq", "1.8.1", cdx.HashAlgoSHA256,
				"8af7dd1115b74cd1db976b0aed6a56afef391c845b644be1652084c13a445692")
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
			// child app has NO own packages directive, but inherits parent base-builder's os-pm packages.
			sbomtest.AssertHasComponent(bom, "jq", "1.8.1")
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
