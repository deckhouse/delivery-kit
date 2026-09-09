package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/os_pm/metadata"
)

var _ = Describe("alternative manager version validation", func() {
	DescribeTable("validates versions with semver", func(version string, expectedError bool) {
		directive := &PackagesDirective{
			Type:      PackagesDirectiveTypeJavaScriptYarn,
			FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: version},
		}
		if expectedError {
			Expect(directive.validate()).To(HaveOccurred())
			return
		}
		Expect(directive.validate()).To(Succeed())
	},
		Entry("missing version", "", true),
		Entry("malformed version", "not-a-version", true),
		Entry("prerelease version", "1.2.3-rc.1", false),
		Entry("build metadata version", "1.2.3+build.7", false),
		Entry("combined prerelease and build metadata", "1.2.3-rc.1+build.7", false),
	)
})

var _ = Describe("package ecosystem registration", func() {
	It("registers os-pm with SBOM-owned metadata", func() {
		ecosystem, ok := Ecosystems()[PackagesDirectiveTypeOSPM]
		Expect(ok).To(BeTrue())
		Expect(ecosystem.DefaultSpecFile).To(BeEmpty())
		Expect(ecosystem.DefaultLockFile).To(BeEmpty())
		Expect(ecosystem.CatalogerName).To(Equal(metadata.CatalogerName))
		Expect(isAlternativeManager(PackagesDirectiveTypeOSPM)).To(BeFalse())
	})

	It("retains cataloger ownership for all package ecosystems", func() {
		registry := Ecosystems()
		Expect(registry[PackagesDirectiveTypeJavaScriptYarn].CatalogerName).To(Equal("javascript-lock-cataloger"))
		Expect(registry[PackagesDirectiveTypeJavaScriptPnpm].CatalogerName).To(Equal("javascript-lock-cataloger"))
		Expect(registry[PackagesDirectiveTypePythonUV].CatalogerName).To(Equal("python-package-cataloger"))
		Expect(registry[PackagesDirectiveTypePythonPoetry].CatalogerName).To(Equal("python-package-cataloger"))
	})

	It("accepts mixed JavaScript and Python alternative directives", func() {
		for _, typeName := range []PackagesDirectiveType{
			PackagesDirectiveTypeJavaScriptYarn,
			PackagesDirectiveTypeJavaScriptPnpm,
			PackagesDirectiveTypePythonUV,
			PackagesDirectiveTypePythonPoetry,
		} {
			Expect(isAlternativeManager(typeName)).To(BeTrue(), string(typeName))
		}
		Expect(isAlternativeManager(PackagesDirectiveTypeJavaScriptNpm)).To(BeFalse())
		Expect(isAlternativeManager(PackagesDirectiveTypePythonPip)).To(BeFalse())
	})

	It("marks only supported alternative managers", func() {
		for _, typ := range []PackagesDirectiveType{
			PackagesDirectiveTypeJavaScriptYarn,
			PackagesDirectiveTypeJavaScriptPnpm,
			PackagesDirectiveTypePythonUV,
			PackagesDirectiveTypePythonPoetry,
		} {
			Expect(isAlternativeManager(typ)).To(BeTrue(), string(typ))
		}

		for _, typ := range []PackagesDirectiveType{
			PackagesDirectiveTypeJavaScriptNpm,
			PackagesDirectiveTypePythonPip,
			PackagesDirectiveTypeGoMod,
			PackagesDirectiveTypeRustCargo,
			PackagesDirectiveTypeLuaRock,
			PackagesDirectiveTypeOSPM,
		} {
			Expect(isAlternativeManager(typ)).To(BeFalse(), string(typ))
		}
	})
})
