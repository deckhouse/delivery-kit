package e2e_build_test

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM python-pip packages", Label("e2e", "sbom", "pip", "simple"), func() {
	It("catalogs requirements.txt dependencies into the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		requests := sbomtest.FindComponent(bom, "requests", "2.32.3")
		Expect(requests).NotTo(BeNil(),
			"expected requests@2.32.3 (from requirements.txt) not found in BOM")
	})

	It("installs with pip even when the project ships a module named pip", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_module_shadow"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_module_shadow")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		requests := sbomtest.FindComponent(bom, "requests", "2.32.3")
		Expect(requests).NotTo(BeNil(),
			"expected requests@2.32.3 in BOM: the project pip.py shadowed the installer and the packages stage reported success without installing anything")
	})

	It("records which files of the image each pip package consists of", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_shipped_files"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		requests := sbomtest.FindComponent(bom, "requests", "2.32.3")
		Expect(requests).NotTo(BeNil(), "expected requests@2.32.3 in BOM")
		Expect(requests.Evidence).NotTo(BeNil(), "requests carries no evidence: the files it consists of were not recorded")
		Expect(requests.Evidence.Occurrences).NotTo(BeNil(), "requests carries no occurrences: the files it consists of were not recorded")

		occurrences := *requests.Evidence.Occurrences
		Expect(occurrences).NotTo(BeEmpty(), "requests is installed, so its files are in the image")
		for _, occurrence := range occurrences {
			Expect(occurrence.Location).To(HavePrefix("/"), "an occurrence names an absolute path in the image")
			Expect(occurrence.Location).To(ContainSubstring("requests"), "an occurrence of requests names one of its files")
			Expect(occurrence.AdditionalContext).To(Or(MatchRegexp(`^sha256:[0-9a-f]{64}$`), Equal("symlink")),
				"every occurrence werf writes carries the file digest or marks a symlink")
		}
		Expect(occurrences).To(ContainElement(HaveField("Location", HaveSuffix("/requests/__init__.py"))))
	})

	It("marks a package of the donor whose files the importing image does not carry", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_partial_import"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_partial_import")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		bomOf := func(image string) *cdx.BOM {
			return sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{image}},
			}))
		}

		shippedProperty := func(comp *cdx.Component) (string, bool) {
			for _, property := range lo.FromPtr(comp.Properties) {
				if property.Name == shippedscope.PropertyShipped {
					return property.Value, true
				}
			}

			return "", false
		}

		donorBOM := bomOf("donor")
		installed := sbomtest.FindComponent(donorBOM, "requests", "2.32.3")
		Expect(installed).NotTo(BeNil(), "expected requests@2.32.3 in the BOM of the image that installs it")
		_, marked := shippedProperty(installed)
		Expect(marked).To(BeFalse(), "the image that installed requests holds its files, so it must not be marked")

		for _, comp := range lo.FromPtr(donorBOM.Components) {
			_, marked := shippedProperty(&comp)
			Expect(marked).To(BeFalse(), "the image that installed its packages ships them: %s@%s is marked", comp.Name, comp.Version)
		}

		// The importing image takes one file of the donor and inherits the donor's whole BOM
		// with it, requests included, while none of the files requests consists of came along.
		inherited := sbomtest.FindComponent(bomOf("app"), "requests", "2.32.3")
		Expect(inherited).NotTo(BeNil(), "expected requests@2.32.3 to be inherited into the BOM of the importing image")
		value, marked := shippedProperty(inherited)
		Expect(marked).To(BeTrue(), "requests is in the BOM of an image that carries none of its files, so it must be marked")
		Expect(value).To(Equal("false"))
	})
})
