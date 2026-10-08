package image

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
)

var _ = Describe("hasFileBasedPackagesWithoutStageDependencies", func() {
	newImageConfig := func(pkgTypes ...config.PackagesDirectiveType) *config.StapelImageBase {
		imageBaseConfig := &config.StapelImageBase{Name: "app"}
		for _, pkgType := range pkgTypes {
			imageBaseConfig.Packages = append(imageBaseConfig.Packages, &config.PackagesDirective{Type: pkgType})
		}
		return imageBaseConfig
	}

	newGitMapping := func(packagesDeps ...string) *stage.GitMapping {
		gitMapping := stage.NewGitMapping()
		gitMapping.StagesDependencies = map[stage.StageName][]string{
			stage.Packages: packagesDeps,
		}
		return gitMapping
	}

	DescribeTable("warning decision",
		func(imageBaseConfig *config.StapelImageBase, gitMappings []*stage.GitMapping, expected bool) {
			Expect(hasFileBasedPackagesWithoutStageDependencies(imageBaseConfig, gitMappings)).To(Equal(expected))
		},
		Entry("file-based packages without stageDependencies.packages",
			newImageConfig(config.PackagesDirectiveTypeGoMod),
			[]*stage.GitMapping{newGitMapping()},
			true,
		),
		Entry("file-based packages mixed with os-pm, no stageDependencies.packages",
			newImageConfig(config.PackagesDirectiveTypeOSPM, config.PackagesDirectiveTypePythonPip),
			[]*stage.GitMapping{newGitMapping()},
			true,
		),
		Entry("file-based packages with stageDependencies.packages declared",
			newImageConfig(config.PackagesDirectiveTypeGoMod),
			[]*stage.GitMapping{newGitMapping("go.mod", "go.sum")},
			false,
		),
		Entry("file-based packages with stageDependencies.packages on one of several mappings",
			newImageConfig(config.PackagesDirectiveTypeGoMod),
			[]*stage.GitMapping{newGitMapping(), newGitMapping("go.mod")},
			false,
		),
		Entry("only os-pm packages",
			newImageConfig(config.PackagesDirectiveTypeOSPM),
			[]*stage.GitMapping{newGitMapping()},
			false,
		),
		Entry("no packages at all",
			newImageConfig(),
			[]*stage.GitMapping{newGitMapping()},
			false,
		),
		Entry("file-based packages without git mappings",
			newImageConfig(config.PackagesDirectiveTypeGoMod),
			nil,
			false,
		),
	)
})

var _ = Describe("packages stage without build.sbom", func() {
	werfYaml := func(sbomBlock string) string {
		return fmt.Sprintf(`project: test
configVersion: 1
%s
---
image: app
from: golang:1.24
git:
- add: /src
  to: /app
  stageDependencies:
    packages: ["go.mod", "go.sum"]
packages:
- type: go-mod
  workdir: /app
`, sbomBlock)
	}

	newRepo := func(ctx context.Context, sbomBlock string) string {
		return newProjectRepo(ctx, map[string]string{
			"werf.yaml":  werfYaml(sbomBlock),
			"src/go.mod": "module example.com/app\n",
			"src/go.sum": "",
		})
	}

	DescribeTable("generates the packages stage regardless of build.sbom.enable",
		func(sbomBlock string) {
			ctx := context.Background()
			projectDir := newRepo(ctx, sbomBlock)

			image, err := stapelImage(ctx, projectDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(stageNames(image)).To(ContainElement(stage.Packages))
		},
		Entry("build.sbom absent", ""),
		Entry("build.sbom.enable false", "build:\n  sbom:\n    enable: false"),
		Entry("build.sbom.enable true", "build:\n  sbom:\n    enable: true\n    standard: cyclonedx@1.6"),
	)
})
