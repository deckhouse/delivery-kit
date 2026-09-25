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
	It("scratch image with default GOST: yes/yes applied to metadata.component", func(ctx SpecContext) {
		setupSbomBuildEnv()

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

		// Scratch image has no packages — GOST lives on metadata.component only.
		// Project-level defaults must land there.
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertyAttackSurface, gost.GostValueYes)
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertySecurityFunction, gost.GostValueYes)
		Expect(bom.Components).To(BeNil(),
			"scratch BOM must not carry package components")
	})

	It("scratch image: image-level GOST overrides project-level GOST", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_gost_meta_image"
		SuiteData.InitTestRepo(ctx, repoDirname, "gost/meta_image")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, nil)

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		// Scratch image has no packages — GOST lives on metadata.component only.
		// Image-level attackSurface override wins; securityFunction stays at project default.
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertyAttackSurface, gost.GostValueNo)
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertySecurityFunction, gost.GostValueYes)
		Expect(bom.Components).To(BeNil(),
			"scratch BOM must not carry package components")
	})

	It("os-pm image: image-level GOST overrides applied to collected components", func(ctx SpecContext) {
		setupSbomBuildEnv()

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
		sbomtest.AssertHasComponent(bom, "jq", "1.8.1")
		// Image-level GOST override for an os-pm image must land on both
		// metadata.component and every collected pm component.
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertyAttackSurface, gost.GostValueNo)
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertySecurityFunction, gost.GostValueIndirect)
		sbomtest.AssertGostPropertyOnComponents(bom, gost.PropertyAttackSurface, gost.GostValueNo)
		sbomtest.AssertGostPropertyOnComponents(bom, gost.PropertySecurityFunction, gost.GostValueIndirect)
	})

	DescribeTable("the source language of the packages directive lands on its components",
		func(ctx SpecContext, ecosystem, fixture, componentName, componentVersion, expectedLang string) {
			setupSbomBuildEnv()

			repoDirname := "repo_sbom_gost_source_langs_" + ecosystem
			SuiteData.InitTestRepo(ctx, repoDirname, fixture)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-gost-source-langs-builder-"+ecosystem)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			sbomtest.AssertSourceLangsOnComponent(bom, componentName, componentVersion, []string{expectedLang})
		},
		Entry("python-pip", "pip", "inject/pip_simple", "requests", "2.32.3", "Python"),
		Entry("javascript-npm", "npm", "inject/npm_simple", "lodash", "4.17.21", "JavaScript"),
	)
})
