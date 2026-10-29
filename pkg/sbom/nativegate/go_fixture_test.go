package nativegate

import (
	"bytes"
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Real pure-Go producer fixture", func() {
	ginkgo.It("verifies an empty Go module mapping and retains the producer composition", func(ctx ginkgo.SpecContext) {
		body, expected, policy := pureGoFixture()
		bom := cdx.NewBOM()
		gomega.Expect(Apply(ctx, policy, "app", fixtureImage(map[string]string{"/app": string(body)}), nil, bom)).To(gomega.Succeed())
		libraries := map[string]string{}
		for _, component := range *bom.Components {
			if component.Type == cdx.ComponentTypeLibrary {
				libraries[component.Name] = component.Version
			}
		}
		gomega.Expect(libraries).To(gomega.Equal(map[string]string{"sbom.test/app": "0.0.1", "golang": "1.27.3"}))
		catalog, err := inherited([]*cdx.BOM{bom})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.Records).To(gomega.HaveLen(1))
		gomega.Expect(catalog.Records[0].Profile).To(gomega.Equal("go"))
		gomega.Expect(catalog.Records[0].Composition).To(gomega.MatchJSON(expected))
	})

	ginkgo.It("rejects Go buildinfo that contradicts the recorded platform", func(ctx ginkgo.SpecContext) {
		body, _, policy := pureGoFixture()
		file, err := elf.NewFile(bytes.NewReader(body))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		info := file.Section(".go.buildinfo")
		gomega.Expect(info).NotTo(gomega.BeNil())
		data, err := info.Data()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		offset := bytes.Index(data, []byte("GOOS=linux"))
		gomega.Expect(offset).To(gomega.BeNumerically(">=", 0))
		gomega.Expect(file.Close()).To(gomega.Succeed())
		copy(body[info.Offset+uint64(offset):], "GOOS=other")
		err = Apply(ctx, policy, "app", fixtureImage(map[string]string{"/app": string(body)}), nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`Go buildinfo GOOS="other" contradicts profile (expected "linux")`)))
	})
})
