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
				"e268b38b239a1217a8f0be27425eca1f14debb4de391b8bf8eb1a03ba0882340")
			// pm uses a placeholder originalRepo for all packages; the real short-repo path
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
				"77f5cedc32ab27157427bee46076a1d3756f9f99785cc0be740e0b276295d688")

			// CPE enrichment: curl has a curated vendor override (haxx) that must win
			// as the primary CPE regardless of URL/repo/name-derived candidates. The
			// name-derived alternative (curl:curl) must be preserved as an evidence
			// candidate so downstream NVD matchers can still hit it.
			sbomtest.AssertHasCPE(bom, "curl", "8.12.1",
				"cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*")
			sbomtest.AssertHasCPECandidate(bom, "curl", "8.12.1",
				"cpe:2.3:a:curl:curl:8.12.1:*:*:*:*:*:*:*")
			// openssl has no curated override in the pm fixture and originalRepo is a
			// placeholder, so the exact primary depends on URL/repo derivation; still,
			// any inferred CPE must be present.
			sbomtest.AssertHasAnyCPE(bom, "openssl", "3.6.2")

			// dependency graph: curl depends on openssl. bom-ref uses lowercase qualifier key
			// containerfactoryversion (werf's cyclonedx serializer lowercases keys in bom-ref).
			sbomtest.AssertDependsOn(bom,
				"pkg:generic/curl@8.12.1?containerfactoryversion=v1.3.6",
				"pkg:generic/openssl@3.6.2?containerfactoryversion=v1.3.6",
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
				"c8336383b9a8de6393af6254acd305823a3db4dbb091a7ea865bbbf95e8cc899")

			// CPE enrichment must survive base+child merge for both the child's own
			// curl (deterministic curated haxx vendor) and the inherited jq.
			sbomtest.AssertHasCPE(bom, "curl", "8.12.1",
				"cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*")
			sbomtest.AssertHasAnyCPE(bom, "jq", "1.8.1")
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
			// inherited pm components must still carry CPE evidence in the child's SBOM.
			sbomtest.AssertHasAnyCPE(bom, "jq", "1.8.1")
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("build fails when pm binary is missing in the image despite os-pm packages declared",
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
				ContainSubstring("Code: 127"),
				ContainSubstring("container run failed"),
			), "expected pm binary missing or build failure; got:\n%s", out)
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
			Expect(out).To(SatisfyAny(
				ContainSubstring("pm: not found"),
				ContainSubstring("pm: command not found"),
			), "expected pm-binary-missing diagnostic; got:\n%s", out)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("resolves pm env from build secrets on a scratch base image without own coreutils",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_packages_scratch_secrets"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_scratch_secrets")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-packages-scratch-secrets-builder")
			// The app image is built from scratch, so PACKAGES_VERSION and REGISTRY
			// reach the packages stage only as build secrets mounted under
			// /run/secrets, resolved by the snapshot command via stapel coreutils.
			buildEnv := append(builderEnv,
				"PACKAGES_VERSION=v1.3.6",
				"REGISTRY=registry.deckhouse.io/container-factory",
			)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: buildEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      buildEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)

			sbomtest.AssertHasComponent(bom, "curl", "8.12.1")
			// the containerfactoryversion purl qualifier proves the secret value made
			// it into /var/lib/pm/container-factory-version inside the scratch image.
			sbomtest.AssertDependsOn(bom,
				"pkg:generic/curl@8.12.1?containerfactoryversion=v1.3.6",
				"pkg:generic/openssl@3.6.2?containerfactoryversion=v1.3.6",
			)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
