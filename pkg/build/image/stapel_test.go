package image

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/stage"
	"github.com/werf/werf/v2/pkg/config"
)

var _ = Describe("shouldWarnFileBasedPackagesWithoutStageDependencies", func() {
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
			Expect(shouldWarnFileBasedPackagesWithoutStageDependencies(imageBaseConfig, gitMappings)).To(Equal(expected))
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
