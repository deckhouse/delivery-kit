package nativegate

import (
	"debug/elf"
	"encoding/json"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Go external link objects", func() {
	ginkgo.It("reads the complete shared go-link-object record", func() {
		data, err := os.ReadFile("testdata/go-link-object.json")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var payload struct {
			SBOM map[string]any `json:"sbom"`
		}
		gomega.Expect(json.Unmarshal(data, &payload)).To(gomega.Succeed())
		reader := inspector{policy: strictPolicy("linux/amd64"), catalog: &Catalog{Components: map[string]cdx.Component{}}}
		record, native, err := reader.inspect(fixtureELF(elf.ET_REL, payload.SBOM))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(native).To(gomega.BeTrue())
		gomega.Expect(record.Profile).To(gomega.Equal("go-link-object"))
	})
})
