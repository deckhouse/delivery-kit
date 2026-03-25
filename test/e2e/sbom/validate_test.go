package e2e_build_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("sbom validate", Label("e2e", "sbom", "validate"), func() {
	It("should succeed with valid --path and --sbom-type oss", func(ctx SpecContext) {
		tmpFile := filepath.Join(GinkgoT().TempDir(), "sbom.json")
		Expect(os.WriteFile(tmpFile, []byte("{}"), 0o644)).To(Succeed())

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--path", tmpFile, "--sbom-type", "oss"},
			},
		})
		_ = out
	})

	It("should succeed with valid --path and --sbom-type container", func(ctx SpecContext) {
		tmpFile := filepath.Join(GinkgoT().TempDir(), "sbom.json")
		Expect(os.WriteFile(tmpFile, []byte("{}"), 0o644)).To(Succeed())

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--path", tmpFile, "--sbom-type", "container"},
			},
		})
		_ = out
	})

	It("should succeed with valid --path, --sbom-type, and --check-vcs", func(ctx SpecContext) {
		tmpFile := filepath.Join(GinkgoT().TempDir(), "sbom.json")
		Expect(os.WriteFile(tmpFile, []byte("{}"), 0o644)).To(Succeed())

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--path", tmpFile, "--sbom-type", "oss", "--check-vcs"},
			},
		})
		_ = out
	})

	It("should succeed with multiple --path arguments", func(ctx SpecContext) {
		tmpDir := GinkgoT().TempDir()
		tmpFile1 := filepath.Join(tmpDir, "sbom1.json")
		tmpFile2 := filepath.Join(tmpDir, "sbom2.json")

		Expect(os.WriteFile(tmpFile1, []byte("{}"), 0o644)).To(Succeed())
		Expect(os.WriteFile(tmpFile2, []byte("{}"), 0o644)).To(Succeed())

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out := werfProject.SbomValidate(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--path", tmpFile1, "--path", tmpFile2, "--sbom-type", "oss"},
			},
		})
		_ = out
	})

	It("should fail when --path is missing", func(ctx SpecContext) {
		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--sbom-type", "oss"},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("path"))
	})

	It("should fail when --sbom-type is missing", func(ctx SpecContext) {
		tmpFile := filepath.Join(GinkgoT().TempDir(), "sbom.json")
		Expect(os.WriteFile(tmpFile, []byte("{}"), 0o644)).To(Succeed())

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--path", tmpFile},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("sbom-type"))
	})

	It("should fail with invalid --sbom-type value", func(ctx SpecContext) {
		tmpFile := filepath.Join(GinkgoT().TempDir(), "sbom.json")
		Expect(os.WriteFile(tmpFile, []byte("{}"), 0o644)).To(Succeed())

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		_, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--path", tmpFile, "--sbom-type", "invalid"},
			},
		})
		Expect(err).To(HaveOccurred())
	})

	It("should show all flags in --help", func(ctx SpecContext) {
		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		out, err := werfProject.SbomValidateWithErr(ctx, &werf.SbomValidateOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--help"},
			},
		})
		_ = err
		Expect(out).To(ContainSubstring("--path"))
		Expect(out).To(ContainSubstring("--sbom-type"))
		Expect(out).To(ContainSubstring("--check-vcs"))
	})
})
