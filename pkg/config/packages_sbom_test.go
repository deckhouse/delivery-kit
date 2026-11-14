package config

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("package source recording", func() {
	ginkgo.It("records pm sources only in SBOM builds and includes it in the cache input", func() {
		packages := []*PackagesDirective{{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"zlib"}}}}
		ordinary := renderPackagesCommands(packages, false)
		instrumented := renderPackagesCommands(packages, true)
		gomega.Expect(ordinary[0].run).NotTo(gomega.ContainSubstring("--sbom-sources-file"))
		gomega.Expect(instrumented[0].run).To(gomega.ContainSubstring("pm install --sbom-sources-file /var/lib/pm/sbom-sources.json zlib"))
		gomega.Expect(instrumented[0].digest).To(gomega.ContainSubstring("--sbom-sources-file"))
		gomega.Expect(packages[0].Spec.Packages).To(gomega.Equal([]string{"zlib"}))
	})
})
