package e2e_build_test

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("sbom validate", Label("e2e", "sbom", "validate"), func() {
	var gitWorkTree string

	BeforeEach(func() {
		absPath, err := filepath.Abs("../../..")
		Expect(err).NotTo(HaveOccurred())
		gitWorkTree = absPath
	})

	fixturePath := func(name string) string {
		absPath, err := filepath.Abs(filepath.Join("_fixtures", "validate", name+".json"))
		Expect(err).NotTo(HaveOccurred())
		return absPath
	}

	commonArgs := func() []string {
		return []string{"--git-work-tree", gitWorkTree, "--dir", gitWorkTree}
	}

	DescribeTable("should pass validation",
		func(ctx SpecContext, fixtures []string, sbomType string, extraFlags []string) {
			args := commonArgs()
			for _, f := range fixtures {
				args = append(args, "--path", fixturePath(f))
			}
			args = append(args, "--sbom-type", sbomType)
			args = append(args, extraFlags...)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: args},
			})
			Expect(out).To(ContainSubstring("OK"))
		},
		Entry("valid OSS SBOM", []string{"valid_oss"}, "oss", []string(nil)),
		Entry("valid container SBOM", []string{"valid_container"}, "container", []string(nil)),
		Entry("multiple valid files", []string{"valid_oss", "valid_container"}, "oss", []string(nil)),
		Entry("with --check-vcs flag", []string{"valid_oss"}, "oss", []string{"--check-vcs"}),
	)

	DescribeTable("should fail validation",
		func(ctx SpecContext, fixtures []string, sbomType, expectedSubstring string) {
			args := commonArgs()
			for _, f := range fixtures {
				args = append(args, "--path", fixturePath(f))
			}
			args = append(args, "--sbom-type", sbomType)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: args},
			})
			Expect(err).To(HaveOccurred())
			if expectedSubstring != "" {
				Expect(out).To(ContainSubstring(expectedSubstring))
			}
		},
		Entry("missing bomFormat", []string{"missing_bom_format"}, "oss", "bomFormat"),
		Entry("wrong bomFormat", []string{"wrong_bom_format"}, "oss", "CycloneDX"),
		Entry("missing version", []string{"missing_version"}, "oss", "version"),
		Entry("missing metadata", []string{"missing_metadata"}, "oss", "metadata"),
		Entry("additional properties", []string{"additional_property"}, "oss", "Additional properties"),
		Entry("container bad GOST", []string{"container_bad_gost"}, "container", ""),
		Entry("multiple files with one invalid", []string{"valid_oss", "missing_bom_format"}, "oss", "bomFormat"),
	)

	It("should fail when file does not exist", func(ctx SpecContext) {
		args := commonArgs()
		args = append(args, "--path", "/nonexistent/sbom.json", "--sbom-type", "oss")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		_, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args},
		})
		Expect(err).To(HaveOccurred())
	})
})
