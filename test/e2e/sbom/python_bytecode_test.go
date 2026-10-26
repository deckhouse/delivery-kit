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

var _ = Describe("SBOM python-pip legacy bytecode", Label("e2e", "sbom", "pip", "simple", "python-bytecode"), func() {
	It("credits sourceless legacy bytecode to the distribution whose RECORD declares its source", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_bytecode"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/python_bytecode")
		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))

		const sitePackages = "/usr/lib/python3.12/site-packages"
		keptBytecode := []string{
			sitePackages + "/bytekept/__init__.pyc",
			sitePackages + "/bytekept/stamp.pyc",
			sitePackages + "/bytekept/checked.pyc",
			sitePackages + "/bytekept/unchecked.pyc",
		}
		droppedBytecode := []string{
			sitePackages + "/bytedropped/__init__.pyc",
			sitePackages + "/bytedropped/legacy.pyc",
		}
		images := []string{"donor", "source", "grandchild", "empty"}
		carriesKept := map[string]bool{"donor": true, "source": true, "grandchild": true}
		carriesDropped := map[string]bool{"donor": true}

		propertyValues := func(comp *cdx.Component, name string) []string {
			return lo.FilterMap(lo.FromPtr(comp.Properties), func(property cdx.Property, _ int) (string, bool) {
				return property.Value, property.Name == name
			})
		}

		assertComponent := func(imageName string, bom *cdx.BOM, name string, bytecode []string, carried bool) cdx.Component {
			comp := sbomtest.FindComponent(bom, name, "0.1.0")
			Expect(comp).NotTo(BeNil(), "%s must retain %s@0.1.0", imageName, name)
			Expect(propertyValues(comp, shippedscope.PropertyFiles)).NotTo(ContainElement("unknown"),
				"%s: a wheel install records every file of %s", imageName, name)

			Expect(comp.Evidence).NotTo(BeNil(), "%s: %s carries no file evidence", imageName, name)
			occurrences := lo.FromPtr(comp.Evidence.Occurrences)
			for _, location := range bytecode {
				Expect(occurrences).To(ContainElement(And(
					HaveField("Location", Equal(location)),
					HaveField("AdditionalContext", MatchRegexp(`^sha256:[0-9a-f]{64}$`)),
				)), "%s: the legacy bytecode of a source %s declares must be its evidence", imageName, name)
			}

			shipped := propertyValues(comp, shippedscope.PropertyShipped)
			if carried {
				Expect(shipped).NotTo(ContainElement("false"), "%s carries the bytecode of %s", imageName, name)
			} else {
				Expect(shipped).NotTo(BeEmpty(), "%s carries none of the files of %s, so it must be marked", imageName, name)
				Expect(shipped).To(HaveEach(Equal("false")), "%s carries none of the files of %s, so it must be marked", imageName, name)
			}

			return *comp
		}

		assertImages := func() map[string]any {
			snapshot := make(map[string]any)
			for _, imageName := range images {
				bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
					CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}},
				}))

				snapshot[imageName+"/bytekept"] = assertComponent(imageName, bom, "bytekept", keptBytecode, carriesKept[imageName])
				snapshot[imageName+"/bytedropped"] = assertComponent(imageName, bom, "bytedropped", droppedBytecode, carriesDropped[imageName])
				snapshot[imageName+"/digest"] = stagesImageDigestOf(ctx, werfProject, imageName)
			}

			return snapshot
		}

		By("compiling two installed packages to sourceless legacy bytecode and importing one of them")
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		initial := assertImages()

		By("reusing both image and SBOM caches")
		out := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(out).To(ContainSubstring("Use previously built image"))
		Expect(out).NotTo(ContainSubstring("Building stage"))
		Expect(out).To(ContainSubstring("image donor: Use previously generated SBOM from registry"))
		Expect(assertImages()).To(Equal(initial))
	})
})
