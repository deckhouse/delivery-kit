package e2e_build_test

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("sbom validate", Label("e2e", "sbom", "validate", "simple"), func() {
	fixturePath := func(name string) string {
		absPath, err := filepath.Abs(filepath.Join("_fixtures", "validate", name+".json"))
		Expect(err).NotTo(HaveOccurred())
		return absPath
	}

	DescribeTable("should pass validation",
		func(ctx SpecContext, fixtures []string, isprasFormat string, extraFlags []string, expectedSubstring string) {
			var args []string
			for _, f := range fixtures {
				args = append(args, "--path", fixturePath(f))
			}
			args = append(args, "--ispras-format", isprasFormat)
			args = append(args, extraFlags...)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: args},
			})
			Expect(out).To(ContainSubstring("OK"))
			if expectedSubstring != "" {
				Expect(out).To(ContainSubstring(expectedSubstring))
			}
		},
		Entry("valid OSS SBOM", []string{"valid_oss"}, "oss", []string(nil), ""),
		Entry("valid container SBOM", []string{"valid_container"}, "container", []string(nil), ""),
		Entry("valid OSS with multiple components", []string{"valid_oss_multiple_components"}, "oss", []string(nil), ""),
		Entry("valid OSS with VCS reference", []string{"valid_oss_with_vcs"}, "oss", []string(nil), ""),
		Entry("valid container with multiple containers", []string{"valid_container_multiple"}, "container", []string(nil), ""),
		Entry("multiple valid OSS files", []string{"valid_oss", "valid_oss_multiple_components"}, "oss", []string(nil), ""),
		Entry("multiple valid container files", []string{"valid_container", "valid_container_multiple"}, "container", []string(nil), ""),
		Entry("multiple valid files mixed", []string{"valid_oss", "valid_container"}, "oss", []string(nil), ""),
		Entry("with --check-vcs flag", []string{"valid_oss"}, "oss", []string{"--check-vcs"}, ""),
		Entry("warnings only pass by default", []string{"oss_multiple_vcs_urls"}, "oss", []string(nil), "OK (1 warning(s))"),
	)

	DescribeTable("should fail validation",
		func(ctx SpecContext, fixtures []string, isprasFormat string, extraFlags []string, expectedSubstring string) {
			var args []string
			for _, f := range fixtures {
				args = append(args, "--path", fixturePath(f))
			}
			args = append(args, "--ispras-format", isprasFormat)
			args = append(args, extraFlags...)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
			out, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: args},
			})
			Expect(err).To(HaveOccurred())
			if expectedSubstring != "" {
				Expect(out).To(ContainSubstring(expectedSubstring))
			}
		},
		Entry("missing bomFormat", []string{"missing_bom_format"}, "oss", []string(nil), "bomFormat"),
		Entry("wrong bomFormat", []string{"wrong_bom_format"}, "oss", []string(nil), "CycloneDX"),
		Entry("missing specVersion", []string{"missing_spec_version"}, "oss", []string(nil), "specVersion"),
		Entry("wrong specVersion", []string{"wrong_spec_version"}, "oss", []string(nil), "1.6"),
		Entry("missing version", []string{"missing_version"}, "oss", []string(nil), "version"),
		Entry("version zero", []string{"version_zero"}, "oss", []string(nil), "minimum"),
		Entry("missing metadata", []string{"missing_metadata"}, "oss", []string(nil), "metadata"),
		Entry("missing timestamp in metadata", []string{"missing_timestamp"}, "oss", []string(nil), "timestamp"),
		Entry("missing component in metadata", []string{"missing_component_in_metadata"}, "oss", []string(nil), "component"),
		Entry("missing manufacturer", []string{"missing_manufacturer"}, "oss", []string(nil), "manufacturer"),
		Entry("missing component name", []string{"missing_component_name"}, "oss", []string(nil), "name"),
		Entry("missing component type", []string{"missing_component_type"}, "oss", []string(nil), "type"),
		Entry("empty JSON object", []string{"empty_object"}, "oss", []string(nil), "bomFormat"),
		Entry("additional properties", []string{"additional_property"}, "oss", []string(nil), "Additional properties"),
		Entry("container bad GOST", []string{"container_bad_gost"}, "container", []string(nil), ""),
		Entry("container attack surface mismatch", []string{"container_attack_surface_mismatch"}, "container", []string(nil), ""),
		Entry("warnings with --fail-on-warnings", []string{"oss_multiple_vcs_urls"}, "oss", []string{"--fail-on-warnings"}, "WARNING"),
		Entry("multiple files with one invalid", []string{"valid_oss", "missing_bom_format"}, "oss", []string(nil), "bomFormat"),
		Entry("multiple files all invalid", []string{"missing_bom_format", "missing_version"}, "oss", []string(nil), ""),
		Entry("three files two invalid", []string{"valid_oss", "missing_bom_format", "missing_metadata"}, "oss", []string(nil), ""),
	)

	It("should fail when file does not exist", func(ctx SpecContext) {
		args := []string{"--path", "/nonexistent/sbom.json", "--ispras-format", "oss"}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		_, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args},
		})
		Expect(err).To(HaveOccurred())
	})
})
