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

var _ = Describe("SBOM python-pip editable packages", Label("e2e", "sbom", "pip", "simple", "editable"), func() {
	It("keeps the file evidence of an editable package unknown instead of marking it not shipped", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_editable"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/editable_python")
		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))

		propertyValues := func(comp *cdx.Component, name string) []string {
			return lo.FilterMap(lo.FromPtr(comp.Properties), func(property cdx.Property, _ int) (string, bool) {
				return property.Value, property.Name == name
			})
		}

		assertImages := func() map[string]cdx.Component {
			snapshot := make(map[string]cdx.Component)
			var donorEditable *cdx.Component
			for _, imageName := range []string{"donor", "source", "grandchild", "empty"} {
				bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
					CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}},
				}))

				editable := sbomtest.FindComponent(bom, "werfeditable", "0.1.0")
				Expect(editable).NotTo(BeNil(), "%s must retain the editable package werfeditable@0.1.0", imageName)
				Expect(editable.PackageURL).To(HavePrefix("pkg:pypi/werfeditable@0.1.0"))
				sbomtest.AssertHasLicense(bom, "werfeditable", "0.1.0", "MIT")
				if donorEditable == nil {
					donorEditable = editable
				}
				Expect(editable.PackageURL).To(Equal(donorEditable.PackageURL), "%s must keep the PURL of the editable package", imageName)
				Expect(editable.Licenses).To(Equal(donorEditable.Licenses), "%s must keep the licenses of the editable package", imageName)

				files := propertyValues(editable, shippedscope.PropertyFiles)
				Expect(files).NotTo(BeEmpty(), "%s: an editable install records no source files, so its file evidence must be unknown", imageName)
				Expect(files).To(HaveEach(Equal("unknown")), "%s: an editable install records no source files, so its file evidence must be unknown", imageName)
				Expect(propertyValues(editable, shippedscope.PropertyShipped)).NotTo(ContainElement("false"),
					"%s: missing editable scaffolding does not prove that the package is not shipped", imageName)

				ordinary := sbomtest.FindComponent(bom, "werfordinary", "0.1.0")
				Expect(ordinary).NotTo(BeNil(), "%s must retain the ordinary package werfordinary@0.1.0", imageName)
				sbomtest.AssertHasLicense(bom, "werfordinary", "0.1.0", "MIT")
				Expect(propertyValues(ordinary, shippedscope.PropertyFiles)).NotTo(ContainElement("unknown"),
					"%s: a wheel install records every file of the package", imageName)
				shipped := propertyValues(ordinary, shippedscope.PropertyShipped)
				if imageName == "donor" {
					Expect(shipped).NotTo(ContainElement("false"), "the image that installed werfordinary holds its files")
					Expect(ordinary.Evidence).NotTo(BeNil())
					Expect(lo.FromPtr(ordinary.Evidence.Occurrences)).To(ContainElement(HaveField("Location", HaveSuffix("/werfordinary/__init__.py"))))
				} else {
					Expect(shipped).NotTo(BeEmpty(), "%s carries none of the files of werfordinary, so it must be marked", imageName)
					Expect(shipped).To(HaveEach(Equal("false")), "%s carries none of the files of werfordinary, so it must be marked", imageName)
				}

				snapshot[imageName+"/werfeditable"] = *editable
				snapshot[imageName+"/werfordinary"] = *ordinary
			}

			return snapshot
		}

		By("installing one local project editable and another as an ordinary wheel")
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
