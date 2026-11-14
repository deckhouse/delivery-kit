package nativegate

import (
	"context"
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("shipped archives", func() {
	ginkgo.It("accounts for a pinned pm archive as a package file without member evidence", func() {
		body := fixtureArchive("legacy.o", fixtureELF(elf.ET_REL, nil))
		component := fixtureComponent("pm")
		bom := cdx.NewBOM()
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/usr/lib/lib.a": body}), bom, VerifyOptions{Subject: "builder", Platform: "linux/amd64", Originals: []Original{{Path: "/usr/lib/lib.a", SHA256: fixtureDigest(body), Component: component, Kind: "pm"}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/usr/lib/lib.a"), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "pm"}))))))
	})
	ginkgo.It("accepts an archive with an instrumented member", func() {
		body := fixtureArchive("code.o", fixtureELF(elf.ET_REL, fixtureRecord("c-object", "linux/amd64")))
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/build/library": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64"})).To(gomega.Succeed())
	})
	ginkgo.It("rejects an extensionless archive with an unrecorded member", func() {
		body := fixtureArchive("code.o", fixtureELF(elf.ET_REL, nil))
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/build/library": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/build/library"), gomega.ContainSubstring("code.o"), gomega.ContainSubstring("missing"))))
	})
	ginkgo.It("rejects a thin archive rather than reading files outside the image", func() {
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/build/library": []byte("!<thin>\n")}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/build/library"), gomega.ContainSubstring("thin archive"))))
	})
})
