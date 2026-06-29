package e2e_build_test

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM GOST integration", Label("e2e", "sbom", "gost", "simple"), func() {
	DescribeTable("scratch image with default GOST: yes/yes applied to metadata.component",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_gost_defaults"
			SuiteData.InitTestRepo(ctx, repoDirname, "gost/defaults")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, nil)

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			sbomtest.AssertSpecVersion(bom, cdx.SpecVersion1_6)
			Expect(bom.Metadata).NotTo(BeNil(), "scratch BOM must have metadata")
			Expect(bom.Metadata.Component).NotTo(BeNil(), "scratch BOM must have metadata.component")
			Expect(bom.Metadata.Component.Type).To(Equal(cdx.ComponentTypeContainer))

			sbomtest.AssertGostProperty(bom, gost.PropertyAttackSurface, gost.GostValueYes)
			sbomtest.AssertGostProperty(bom, gost.PropertySecurityFunction, gost.GostValueYes)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("scratch image: image-level GOST overrides project-level GOST",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_gost_meta_image"
			SuiteData.InitTestRepo(ctx, repoDirname, "gost/meta_image")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, nil)

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			sbomtest.AssertGostProperty(bom, gost.PropertyAttackSurface, gost.GostValueNo)
			sbomtest.AssertGostProperty(bom, gost.PropertySecurityFunction, gost.GostValueYes)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)

	DescribeTable("os-pm image: image-level GOST overrides applied to collected components",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_gost_ospm_override"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_gost_override")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-gost-ospm-override-builder")

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
			sbomtest.AssertGostProperty(bom, gost.PropertyAttackSurface, gost.GostValueNo)
			sbomtest.AssertGostProperty(bom, gost.PropertySecurityFunction, gost.GostValueIndirect)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
