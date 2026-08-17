package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/packages/os_pm"
)

var _ = Describe("package ecosystem registration", func() {
	It("registers os-pm with SBOM-owned metadata", func() {
		ecosystem, ok := Ecosystems()[PackagesDirectiveTypeOSPM]
		Expect(ok).To(BeTrue())
		Expect(ecosystem.DefaultSpecFile).To(BeEmpty())
		Expect(ecosystem.DefaultLockFile).To(BeEmpty())
		Expect(ecosystem.CatalogerName).To(Equal(os_pm.CatalogerName))
	})
})
