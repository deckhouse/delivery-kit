package build

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("artifact stage migration", func() {
	It("does not retain transitional SBOM or VEX step implementations", func() {
		root := "."
		var sourceFiles []string
		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			sourceFiles = append(sourceFiles, path)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		for _, path := range sourceFiles {
			contents, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(contents)).NotTo(ContainSubstring("sbom"+"Step"), path)
			Expect(string(contents)).NotTo(ContainSubstring("vex"+"Step"), path)
		}

		buildPhase, err := os.ReadFile("build_phase.go")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buildPhase)).To(ContainSubstring("GenerateSbomStage"))
		Expect(string(buildPhase)).To(ContainSubstring("NewVexStage"))
		Expect(string(buildPhase)).To(ContainSubstring("if len(images) == 1"))
		Expect(string(buildPhase)).To(ContainSubstring("convergeMultiplatformVexByImageSets"))
	})
})
