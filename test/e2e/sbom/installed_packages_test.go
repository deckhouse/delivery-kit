package e2e_build_test

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM installed-packages inventory", Label("e2e", "sbom", "installed", "simple"), func() {
	It("pip: transitive installed packages appear in BOM but not as root dependencies", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_installed_pip"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		}))

		sbomtest.AssertHasComponent(bom, "requests", "2.32.3")

		transitives := []string{"certifi", "charset-normalizer", "idna", "urllib3"}
		for _, name := range transitives {
			comp, found := lo.Find(lo.FromPtr(bom.Components), func(c cdx.Component) bool { return c.Name == name })
			Expect(found).To(BeTrue(), "transitive %s must be in BOM from installed scan", name)
			Expect(comp.Version).NotTo(BeEmpty())
			Expect(lo.FromPtr(comp.Licenses)).NotTo(BeEmpty())
		}

		roots := sbomtest.RootDependencies(bom)
		Expect(roots).To(ContainElement("requests"), "requests is declared and must be a root dependency")
		for _, name := range transitives {
			Expect(roots).NotTo(ContainElement(name), "transitive %s must NOT be a root dependency", name)
		}
	})

	It("npm: dev and nested packages appear in BOM and the source graph is retained", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_installed_npm"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/installed_npm")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		}))

		sbomtest.AssertHasComponent(bom, "is-odd", "3.0.1")
		sbomtest.AssertHasComponent(bom, "is-number", "7.0.0")
		sbomtest.AssertHasComponent(bom, "yocto-queue", "1.1.1")
		sbomtest.AssertHasComponent(bom, "is-number", "6.0.0")

		sbomtest.AssertHasLicense(bom, "is-odd", "3.0.1", "MIT")
		sbomtest.AssertHasLicense(bom, "yocto-queue", "1.1.1", "MIT")

		roots := sbomtest.RootDependencies(bom)
		Expect(roots).To(ContainElement("is-odd"), "is-odd is declared prod dep")
		Expect(roots).To(ContainElement("is-number"), "is-number@7 is declared prod dep")

		isNumber6 := sbomtest.FindComponent(bom, "is-number", "6.0.0")
		Expect(isNumber6).NotTo(BeNil())
		isOdd := sbomtest.FindComponent(bom, "is-odd", "3.0.1")
		Expect(isOdd).NotTo(BeNil())
		sbomtest.AssertDependsOn(bom, isOdd.BOMRef, isNumber6.BOMRef)
	})

	It("lua: transitive rock (say) appears in BOM with license", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_installed_lua"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/installed_lua")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		}))

		Expect(lo.FromPtr(bom.Components)).To(ContainElement(HaveField("Name", "werf-sbom-lua-installed")))
		Expect(lo.FromPtr(bom.Components)).To(ContainElement(HaveField("Name", "luassert")))
		say, found := lo.Find(lo.FromPtr(bom.Components), func(c cdx.Component) bool { return c.Name == "say" })
		Expect(found).To(BeTrue(), "say (transitive of luassert) must be in BOM from installed scan")
		Expect(say.Version).NotTo(BeEmpty())
		sbomtest.AssertHasLicense(bom, "say", say.Version, "MIT")

		roots := sbomtest.RootDependencies(bom)
		Expect(roots).To(ContainElement("werf-sbom-lua-installed"), "app rock is declared")
		Expect(roots).NotTo(ContainElement("say"), "say is transitive, not a root")
	})
})
