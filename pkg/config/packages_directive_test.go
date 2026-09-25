package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/os_pm/metadata"
)

var _ = Describe("package ecosystem registration", func() {
	It("registers os-pm with SBOM-owned metadata", func() {
		ecosystem, ok := Ecosystems()[PackagesDirectiveTypeOSPM]
		Expect(ok).To(BeTrue())
		Expect(ecosystem.DefaultSpecFile).To(BeEmpty())
		Expect(ecosystem.DefaultLockFile).To(BeEmpty())
		Expect(ecosystem.CatalogerName).To(Equal(metadata.CatalogerName))
		Expect(ecosystem.SourceLang).To(BeEmpty())
	})

	DescribeTable("registers the source language of a file-based ecosystem",
		func(directiveType PackagesDirectiveType, expectedLang string) {
			ecosystem, ok := Ecosystems()[directiveType]
			Expect(ok).To(BeTrue())
			Expect(ecosystem.SourceLang).To(Equal(expectedLang))
		},
		Entry("go-mod", PackagesDirectiveTypeGoMod, "Go"),
		Entry("python-uv", PackagesDirectiveTypePythonUV, "Python"),
		Entry("python-pip", PackagesDirectiveTypePythonPip, "Python"),
		Entry("python-poetry", PackagesDirectiveTypePythonPoetry, "Python"),
		Entry("rust-cargo", PackagesDirectiveTypeRustCargo, "Rust"),
		Entry("javascript-npm", PackagesDirectiveTypeJavaScriptNpm, "JavaScript"),
		Entry("javascript-yarn", PackagesDirectiveTypeJavaScriptYarn, "JavaScript"),
		Entry("javascript-pnpm", PackagesDirectiveTypeJavaScriptPnpm, "JavaScript"),
		Entry("lua-rock", PackagesDirectiveTypeLuaRock, "Lua"),
	)
})
