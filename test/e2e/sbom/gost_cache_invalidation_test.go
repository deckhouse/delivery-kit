package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM GOST cache invalidation", Label("e2e", "sbom", "gost", "simple"), func() {
	const (
		sbomCachedMarker    = "Use previously generated SBOM from registry"
		sbomRegenMarker     = "SBOM processing"
		stageBuildingMarker = "Building stage"
	)

	DescribeTable("regenerates SBOM when only the GOST config changes; uses cache when unchanged",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_gost_toggle"
			SuiteData.InitTestRepo(ctx, repoDirname, "gost_toggle/state0")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			By("state0: initial build with GOST yes/yes")
			out0 := werfProject.Build(ctx, nil)
			Expect(out0).To(ContainSubstring(sbomRegenMarker), "expected initial SBOM generation")

			bom0 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
			}))
			sbomtest.AssertGostPropertyOnMetadata(bom0, gost.PropertyAttackSurface, gost.GostValueYes)
			sbomtest.AssertGostPropertyOnMetadata(bom0, gost.PropertySecurityFunction, gost.GostValueYes)

			By("rebuild state0 without changes: SBOM must come from cache")
			outCached := werfProject.Build(ctx, nil)
			Expect(outCached).To(ContainSubstring(sbomCachedMarker),
				"expected cached SBOM marker %q, output was:\n%s", sbomCachedMarker, outCached)

			By("state1: change only the GOST config → image is untouched, SBOM must regenerate")
			SuiteData.UpdateTestRepo(ctx, repoDirname, "gost_toggle/state1")
			out1 := werfProject.Build(ctx, nil)

			// The image content is identical between states (scratch base, no
			// instructions, no packages): the GOST config lives in the SBOM section
			// and feeds no stage digest. Only the SBOM artifact checksum can trigger
			// the regeneration here.
			Expect(out1).NotTo(ContainSubstring(stageBuildingMarker),
				"GOST config change must not rebuild any stage; output:\n%s", out1)
			Expect(out1).To(ContainSubstring(sbomRegenMarker),
				"expected SBOM regeneration after GOST config change; output:\n%s", out1)
			Expect(out1).NotTo(ContainSubstring(sbomCachedMarker),
				"SBOM must not be served from cache after GOST config change; output:\n%s", out1)

			bom1 := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
			}))
			sbomtest.AssertGostPropertyOnMetadata(bom1, gost.PropertyAttackSurface, gost.GostValueNo)
			sbomtest.AssertGostPropertyOnMetadata(bom1, gost.PropertySecurityFunction, gost.GostValueIndirect)
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
		XEntry("with local repo using Native Buildah with chroot isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-chroot"}}),
		XEntry("with local repo using Native Buildah with rootless isolation", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "native-rootless"}}),
	)
})
