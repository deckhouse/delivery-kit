package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// The Go race runtime is shipped as a relocatable object the Go toolchain links
// into -race builds, at the path the distribution expects it under.
const racePath = "/usr/local/go/src/runtime/race/internal/amd64v1/race_linux.syso"

func objectPolicy() *Policy {
	policy := fixturePolicy("image")
	policy.Profiles = []string{"c-object"}
	return policy
}

// partialObjectRecord drops a required field, leaving a record that states
// nothing complete rather than one that contradicts itself.
func partialObjectRecord() map[string]any {
	raw, err := json.Marshal(fixtureBuildRecord(elf.ET_REL))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var record map[string]any
	gomega.Expect(json.Unmarshal(raw, &record)).To(gomega.Succeed())
	delete(record, "tools")
	return record
}

var _ = ginkgo.Describe("shipped relocatable object", func() {
	ginkgo.It("accepts an object carrying its own record and keeps its composition", func() {
		body := minimalRuntimeELF(elf.ET_REL)
		bom := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{racePath: string(body)}), nil, bom)).To(gomega.Succeed())
		catalog, err := ReadCatalog([]*cdx.BOM{bom})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.Records).To(gomega.HaveLen(1))
		gomega.Expect(catalog.Records[0].Path).To(gomega.Equal(racePath))
		gomega.Expect(catalog.Records[0].SHA256).To(gomega.Equal(digest(body)))
		gomega.Expect(catalog.Records[0].Profile).To(gomega.Equal("c-object"))
		var composition shared.BuildRecord
		gomega.Expect(json.Unmarshal(catalog.Records[0].Composition, &composition)).To(gomega.Succeed())
		gomega.Expect(composition.Artifact).To(gomega.Equal("object"))
		gomega.Expect(composition.Profile.Platform).To(gomega.Equal("linux/amd64"))
		gomega.Expect(catalog.Records[0].Components).To(gomega.HaveLen(1))
		component := catalog.Components[catalog.Records[0].Components[0]]
		gomega.Expect(component.Name).To(gomega.Equal(elf.ET_REL.String()))
		gomega.Expect(component.Version).To(gomega.Equal("1"))
	})

	ginkgo.DescribeTable("refuses an object that does not carry a record of itself", func(build func() []byte, expected string) {
		err := Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{racePath: string(build())}), nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		// The replacement name is as long as the original, so nothing but the
		// section's identity changes.
		ginkgo.Entry("no record at all", func() []byte {
			return bytes.Replace(minimalRuntimeELF(elf.ET_REL), []byte(".note.package"), []byte(".note.unknown"), 1)
		}, "no-data"),
		ginkgo.Entry("partial record", func() []byte {
			return runtimeELFWithRecord(elf.ET_REL, partialObjectRecord())
		}, "no-data"),
		ginkgo.Entry("record of an executable, not of this object", func() []byte {
			return runtimeELFWithRecord(elf.ET_REL, fixtureBuildRecord(elf.ET_EXEC))
		}, `invalid: artifact "elf" does not match ELF type ET_REL`),
		ginkgo.Entry("object record on an executable", func() []byte {
			return runtimeELFWithRecord(elf.ET_EXEC, fixtureBuildRecord(elf.ET_REL))
		}, `invalid: artifact "object" does not match ELF type ET_EXEC`),
		// An ar member keeps its own record, but an archive is not that member:
		// which members a link selects is not read here.
		ginkgo.Entry("recorded object inside an archive", func() []byte {
			return append([]byte("!<arch>\n"), minimalRuntimeELF(elf.ET_REL)...)
		}, "unsupported"),
	)

	ginkgo.It("refuses an inherited record whose bytes are another object's", func() {
		body := minimalRuntimeELF(elf.ET_REL)
		first := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{racePath: string(body)}), nil, first)).To(gomega.Succeed())
		record := fixtureBuildRecord(elf.ET_REL)
		record.Components[0].Name = "another-object"
		other := runtimeELFWithRecord(elf.ET_REL, record)
		gomega.Expect(digest(other)).NotTo(gomega.Equal(digest(body)))
		gomega.Expect(Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{racePath: string(other)}), nil, cdx.NewBOM())).To(gomega.Succeed())
		err := Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{racePath: string(other)}), []*cdx.BOM{first}, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("content changed")))
	})

	ginkgo.It("refuses an object whose profile the policy does not allow", func() {
		policy := objectPolicy()
		policy.Profiles = []string{"c-static"}
		err := Apply(context.Background(), policy, "image", fixtureImage(map[string]string{racePath: string(minimalRuntimeELF(elf.ET_REL))}), nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported: build profile c-object")))
	})
})
