package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("embedded composition", func() {
	ginkgo.It("rechecks an unchanged package ELF without confusing ownership and embedded composition", func() {
		body := minimalRuntimeELF(elf.ET_EXEC)
		index, err := json.Marshal(map[string]any{"example": map[string]string{"name": "example", "version": "1", "digest": digest([]byte("package manifest"))}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		files, err := json.Marshal(map[string]any{"example": map[string]any{"version": "1", "files": map[string]string{"/app": digest(body)}, "symlinks": map[string]string{}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		img := fixtureImage(map[string]string{"/app": string(body), "/var/lib/pm/index.json": string(index), "/var/lib/pm/files.json": string(files), "/var/lib/pm/container-factory-version": "v-test"})
		first := cdx.NewBOM()
		policy := fixturePolicy("image")
		gomega.Expect(Apply(context.Background(), policy, "image", img, nil, first)).To(gomega.Succeed())
		raw, err := cyclonedxutil.ToJSON(first)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		restored, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(raw)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		second := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "image", img, []*cdx.BOM{restored}, second)).To(gomega.Succeed())
		original, err := inherited([]*cdx.BOM{restored})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		repeated, err := inherited([]*cdx.BOM{second})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(repeated).To(gomega.Equal(original))
		gomega.Expect(repeated.Records).To(gomega.HaveLen(1))
		gomega.Expect(repeated.Records[0].Owners).To(gomega.HaveLen(1))
		gomega.Expect(repeated.Records[0].Components).To(gomega.HaveLen(2))
	})
	ginkgo.DescribeTable("does not accept a package hash as composition for unsupported binaries", func(body string) {
		catalog := fixtureCatalog()
		catalog.Records[0].SHA256 = digest([]byte(body))
		bom := cdx.NewBOM()
		gomega.Expect(catalog.attach(bom)).To(gomega.Succeed())
		err := Apply(context.Background(), fixturePolicy("image"), "image", fixtureImage(map[string]string{"/bin/a": body}), []*cdx.BOM{bom}, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/bin/a: unsupported")))
	}, ginkgo.Entry("PE", "MZpayload"), ginkgo.Entry("Mach-O", "\xfe\xed\xfa\xcfpayload"), ginkgo.Entry("archive", "!<arch>\npayload"))
	ginkgo.It("reads a standalone artifact and preserves confirmed empty inputs across serialization and rename", func() {
		body := minimalRuntimeELF(elf.ET_EXEC)
		policy := fixturePolicy("build")
		policy.Images["build"] = ImagePolicy{Role: "produce", Outputs: []string{"/app"}}
		bom := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "build", fixtureImage(map[string]string{"/app": string(body)}), nil, bom)).To(gomega.Succeed())
		raw, err := cyclonedxutil.ToJSON(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		restored, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(raw)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		catalog, err := inherited([]*cdx.BOM{restored})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.Records).To(gomega.HaveLen(1))
		var composition shared.BuildRecord
		gomega.Expect(json.Unmarshal(catalog.Records[0].Composition, &composition)).To(gomega.Succeed())
		gomega.Expect(composition.Complete).To(gomega.BeTrue())
		gomega.Expect(composition.Inputs).NotTo(gomega.BeNil())
		gomega.Expect(composition.Inputs).To(gomega.BeEmpty())

		renamed := cdx.NewBOM()
		policy = fixturePolicy("image")
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/renamed": string(body)}), []*cdx.BOM{restored}, renamed)).To(gomega.Succeed())
		after, err := inherited([]*cdx.BOM{renamed})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(after.Records).To(gomega.HaveLen(1))
		gomega.Expect(after.Records[0].Path).To(gomega.Equal("/renamed"))
		gomega.Expect(after.Records[0].SHA256).To(gomega.Equal(digest(body)))
		gomega.Expect(after.Records[0].Composition).To(gomega.MatchJSON(catalog.Records[0].Composition))

		ginkgo.By("rechecking the current profile and tool policy on inherited bytes")
		policy.Profiles = nil
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/renamed": string(body)}), []*cdx.BOM{restored}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("unsupported")))
		policy = fixturePolicy("image")
		policy.Tools = nil
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/renamed": string(body)}), []*cdx.BOM{restored}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("unregistered tool")))
		policy = fixturePolicy("image")
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/app": string(append(body, 0))}), []*cdx.BOM{restored}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("content changed")))

		ginkgo.By("not converting a damaged cached record into confirmed absence")
		composition.Complete = false
		catalog.Records[0].Composition, err = json.Marshal(composition)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.attach(restored)).To(gomega.Succeed())
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/app": string(body)}), []*cdx.BOM{restored}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("no-data")))
	})

	ginkgo.It("replaces a file with independently known content without retaining the old composition", func() {
		oldRecord := fixtureBuildRecord(elf.ET_EXEC)
		newRecord := fixtureBuildRecord(elf.ET_EXEC)
		newRecord.Components[0].Version = "2"
		oldBody, newBody := runtimeELFWithRecord(elf.ET_EXEC, oldRecord), runtimeELFWithRecord(elf.ET_EXEC, newRecord)
		oldBOM, newBOM := cdx.NewBOM(), cdx.NewBOM()
		policy := fixturePolicy("image")
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/app": string(oldBody)}), nil, oldBOM)).To(gomega.Succeed())
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/other": string(newBody)}), nil, newBOM)).To(gomega.Succeed())
		result := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{"/app": string(newBody)}), []*cdx.BOM{oldBOM, newBOM}, result)).To(gomega.Succeed())
		catalog, err := inherited([]*cdx.BOM{result})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.Records).To(gomega.HaveLen(1))
		gomega.Expect(catalog.Records[0].Path).To(gomega.Equal("/app"))
		gomega.Expect(catalog.Records[0].SHA256).To(gomega.Equal(digest(newBody)))
		for _, component := range catalog.Components {
			gomega.Expect(component.Version).To(gomega.Equal("2"))
		}
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(map[string]string{}), []*cdx.BOM{result}, result)).To(gomega.Succeed())
		catalog, err = inherited([]*cdx.BOM{result})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.Records).To(gomega.BeEmpty())
		gomega.Expect(catalog.Components).To(gomega.BeEmpty())
	})

	ginkgo.It("keeps original identities with the same name and version distinct without replaying missing source files", func() {
		record := fixtureBuildRecord(elf.ET_EXEC)
		for _, id := range []string{"a", "b"} {
			record.Components = append(record.Components, shared.BuildComponent{ID: id, Name: "library", Version: "1", Source: shared.BuildSource{Kind: "pm", Locator: "registry.example/library", Checksum: "sha256:" + strings.Repeat(id, 64)}})
			record.Inputs = append(record.Inputs, shared.BuildInput{Kind: "header", Path: "/absent/" + id + ".h", SHA256: "sha256:" + strings.Repeat("c", 64), Components: []string{id}, Disposition: "included"})
		}
		body := runtimeELFWithRecord(elf.ET_EXEC, record)
		bom := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), fixturePolicy("image"), "image", fixtureImage(map[string]string{"/app": string(body)}), nil, bom)).To(gomega.Succeed())
		cyclonedxutil.Canonicalize(context.Background(), bom)
		data, err := cyclonedxutil.ToJSON(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		decoded, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		refs := []string{}
		for _, component := range *decoded.Components {
			if component.Name == "library" {
				refs = append(refs, component.BOMRef)
				gomega.Expect(component.Version).To(gomega.Equal("1"))
			}
		}
		gomega.Expect(refs).To(gomega.HaveLen(2))
		gomega.Expect(refs[0]).NotTo(gomega.Equal(refs[1]))
		for _, dependency := range *decoded.Dependencies {
			if dependency.Ref == digest(body)+":/app" {
				gomega.Expect(*dependency.Dependencies).To(gomega.ContainElements(refs))
			}
		}
	})

	ginkgo.DescribeTable("rejects incomplete and unsupported embedded records", func(mutate func(*shared.BuildRecord), expected string) {
		record := fixtureBuildRecord(elf.ET_EXEC)
		mutate(record)
		body := runtimeELFWithRecord(elf.ET_EXEC, record)
		err := Apply(context.Background(), fixturePolicy("image"), "image", fixtureImage(map[string]string{"/app": string(body)}), nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/app: " + expected)))
	},
		ginkgo.Entry("incomplete", func(r *shared.BuildRecord) { r.Complete = false }, "no-data"),
		ginkgo.Entry("null inputs", func(r *shared.BuildRecord) { r.Inputs = nil }, "invalid"),
		ginkgo.Entry("unknown schema", func(r *shared.BuildRecord) { r.Schema = "pm.buildinfo/v99" }, "unsupported"),
		ginkgo.Entry("unknown profile revision", func(r *shared.BuildRecord) { r.Profile.Revision = json.Number("99") }, "unsupported"),
	)
})
