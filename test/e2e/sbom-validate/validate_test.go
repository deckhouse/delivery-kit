package e2e_sbom_validate_test

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("sbom validate", Label("e2e", "sbom", "validate", "simple"), func() {
	fixturePath := func(name string) string {
		absPath, err := filepath.Abs(filepath.Join("_fixtures", name+".json"))
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
		Entry("valid OSS with warnings and --warnings-non-fatal", []string{"oss_multiple_vcs_urls"}, "oss", []string{"--warnings-non-fatal"}, "OK (1 warning(s))"),
	)

	DescribeTable("should fail validation",
		func(ctx SpecContext, fixtures []string, isprasFormat, expectedSubstring string) {
			var args []string
			for _, f := range fixtures {
				args = append(args, "--path", fixturePath(f))
			}
			args = append(args, "--ispras-format", isprasFormat)

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
		Entry("missing specVersion", []string{"missing_spec_version"}, "oss", "specVersion"),
		Entry("wrong specVersion", []string{"wrong_spec_version"}, "oss", "1.6"),
		Entry("missing version", []string{"missing_version"}, "oss", "version"),
		Entry("version zero", []string{"version_zero"}, "oss", "minimum"),
		Entry("missing metadata", []string{"missing_metadata"}, "oss", "metadata"),
		Entry("missing timestamp in metadata", []string{"missing_timestamp"}, "oss", "timestamp"),
		Entry("missing component in metadata", []string{"missing_component_in_metadata"}, "oss", "component"),
		Entry("missing manufacturer", []string{"missing_manufacturer"}, "oss", "manufacturer"),
		Entry("missing component name", []string{"missing_component_name"}, "oss", "name"),
		Entry("missing component type", []string{"missing_component_type"}, "oss", "type"),
		Entry("empty JSON object", []string{"empty_object"}, "oss", "bomFormat"),
		Entry("additional properties", []string{"additional_property"}, "oss", "Additional properties"),
		Entry("container bad GOST", []string{"container_bad_gost"}, "container", ""),
		Entry("container attack surface mismatch", []string{"container_attack_surface_mismatch"}, "container", ""),
		Entry("warnings alone fail by default", []string{"oss_multiple_vcs_urls"}, "oss", "WARNING"),
		Entry("multiple files with one invalid", []string{"valid_oss", "missing_bom_format"}, "oss", "bomFormat"),
		Entry("multiple files all invalid", []string{"missing_bom_format", "missing_version"}, "oss", ""),
		Entry("three files two invalid", []string{"valid_oss", "missing_bom_format", "missing_metadata"}, "oss", ""),
	)

	It("should print the checker output with --checker-verbose", func(ctx SpecContext) {
		args := []string{"--path", fixturePath("valid_oss"), "--ispras-format", "oss", "--checker-verbose"}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args},
		})
		Expect(out).To(ContainSubstring("Checker output for valid_oss.json"))
		Expect(out).To(ContainSubstring("OK"))
	})

	It("should print warnings on stderr while --warnings-non-fatal keeps stdout clean", func(ctx SpecContext) {
		args := []string{
			"--path", fixturePath("oss_multiple_vcs_urls"),
			"--ispras-format", "oss",
			"--warnings-non-fatal",
		}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		stdout, stderr, err := werfProject.SbomValidateSeparateStreams(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(stdout).To(ContainSubstring("OK (1 warning(s))"))
		Expect(stdout).NotTo(ContainSubstring("WARNING:"))
		Expect(stderr).To(ContainSubstring("WARNING:"))
	})

	It("should keep warnings non-fatal via WERF_WARNINGS_NON_FATAL", func(ctx SpecContext) {
		args := []string{"--path", fixturePath("oss_multiple_vcs_urls"), "--ispras-format", "oss"}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args, Envs: []string{"WERF_WARNINGS_NON_FATAL=true"}},
		})
		Expect(out).To(ContainSubstring("OK (1 warning(s))"))
	})

	It("should let --warnings-non-fatal=false override WERF_WARNINGS_NON_FATAL", func(ctx SpecContext) {
		args := []string{"--path", fixturePath("oss_multiple_vcs_urls"), "--ispras-format", "oss", "--warnings-non-fatal=false"}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args, Envs: []string{"WERF_WARNINGS_NON_FATAL=true"}},
		})
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("WARNING"))
	})

	It("should fail when file does not exist", func(ctx SpecContext) {
		args := []string{"--path", "/nonexistent/sbom.json", "--ispras-format", "oss"}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		_, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: args},
		})
		Expect(err).To(HaveOccurred())
	})
})
