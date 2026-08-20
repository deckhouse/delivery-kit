package metadata

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("os-pm metadata", func() {
	It("defines the runtime paths and cataloger name", func() {
		Expect(ContainerFactoryIndexPath).To(Equal("/var/lib/pm/index.json"))
		Expect(ContainerFactoryVersionPath).To(Equal("/var/lib/pm/container-factory-version"))
		Expect(CatalogerName).To(Equal("pm-cataloger"))
	})
})
