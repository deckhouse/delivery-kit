package nativegate

import (
	"context"
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("shipped archives", func() {
	ginkgo.It("rejects a modified pm archive against its original hash", func() {
		original := fixtureArchive("legacy.o", fixtureELF(elf.ET_REL, nil))
		changed := append(append([]byte{}, original...), []byte("tampered")...)
		filename := "/usr/lib/lib.a"
		err := Verify(context.Background(), fixtureImage(map[string][]byte{filename: changed}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: filename, SHA256: fixtureDigest(original), Kind: "pm", Component: fixtureComponent("pm")}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(filename), gomega.ContainSubstring("hash-mismatch"))))
	})
	ginkgo.It("refuses a Go cache archive when it is actually shipped in the image", func() {
		body := fixtureArchive("__.PKGDEF", []byte("go object linux amd64 go1.27.4\n"))
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/go-cache/package-d": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/go-cache/package-d"), gomega.ContainSubstring("__.PKGDEF"), gomega.ContainSubstring("no-data"))))
	})
	ginkgo.It("accounts for a pinned pm archive as a package file without member evidence", func() {
		body := fixtureArchive("legacy.o", fixtureELF(elf.ET_REL, nil))
		component := fixtureComponent("pm")
		bom := cdx.NewBOM()
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/usr/lib/lib.a": body}), bom, VerifyOptions{Subject: "builder", Platform: "linux/amd64", Originals: []Original{{Path: "/usr/lib/lib.a", SHA256: fixtureDigest(body), Component: component, Kind: "pm"}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/usr/lib/lib.a"), gomega.HaveField("Type", cdx.ComponentTypeFile), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "pm"}))))))
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
