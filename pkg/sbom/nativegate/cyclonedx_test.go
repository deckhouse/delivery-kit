package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"

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
		gomega.Expect(string(data)).NotTo(gomega.ContainSubstring("dk:catalog"))
		gomega.Expect(string(data)).NotTo(gomega.ContainSubstring("/build/"))
		gomega.Expect(string(data)).To(gomega.ContainSubstring("/usr/bin/app"))
		ginkgo.GinkgoWriter.Printf("SBOM_EXAMPLE=%s\n", data)
	})
	ginkgo.It("rejects an invalid file type in the published contract example", func() {
		bom := fixtureContractBOM()
		data, err := json.Marshal(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.Succeed())
		(*bom.Components)[0].Type = cdx.ComponentType("invalid-file-type")
		data, err = json.Marshal(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(json.Valid(data)).To(gomega.BeTrue())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.MatchError(gomega.ContainSubstring("schema validation errors")))
	})
	ginkgo.It("rejects a dangling file dependency in the published contract example", func() {
		bom := fixtureContractBOM()
		_, err := ImageOriginals(context.Background(), bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		file := (*bom.Components)[0]
		gomega.Expect(file.Type).To(gomega.Equal(cdx.ComponentTypeFile))
		changed := false
		for index := range *bom.Dependencies {
			dependency := &(*bom.Dependencies)[index]
			if dependency.Ref == file.BOMRef {
				dependency.Dependencies = &[]string{"urn:missing:component"}
				changed = true
			}
		}
		gomega.Expect(changed).To(gomega.BeTrue())
		data, err := json.Marshal(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.Succeed())
		_, err = ImageOriginals(context.Background(), bom, "linux/amd64")
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(file.Name), gomega.ContainSubstring("missing component urn:missing:component"))))
	})
})
