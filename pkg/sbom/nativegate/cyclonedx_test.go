package nativegate

import (
	"context"
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("native CycloneDX contract", func() {
	ginkgo.It("publishes schema-valid file relationships without a catalog blob", func() {
		bom := cyclonedxutil.NewBOM()
		bom.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "app", BOMRef: "urn:example:image", Version: "1"}}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/usr/bin/app": fixtureELF(elf.ET_EXEC, fixtureRecord("c-static", "linux/amd64"))}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64"})).To(gomega.Succeed())
		cyclonedxutil.Canonicalize(context.Background(), bom)
		data, err := cyclonedxutil.ToJSON(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.Succeed())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema([]byte(`{"bomFormat":"invalid"}`))).NotTo(gomega.Succeed())
		gomega.Expect(string(data)).NotTo(gomega.ContainSubstring("dk:catalog"))
		gomega.Expect(string(data)).NotTo(gomega.ContainSubstring("/build/"))
		gomega.Expect(string(data)).To(gomega.ContainSubstring("/usr/bin/app"))
		ginkgo.GinkgoWriter.Printf("SBOM_EXAMPLE=%s\n", data)
	})
})
