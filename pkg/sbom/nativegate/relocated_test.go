package nativegate

import (
	"context"
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("relocated package files", func() {
	ginkgo.DescribeTable("does not infer ownership from empty content", func(name string, own bool, count int) {
		originals := []Original{{Path: "/usr/share/empty", SHA256: fixtureDigest(nil), Component: fixtureComponent("pm"), Kind: "pm"}}
		if count == 2 {
			originals = append(originals, Original{Path: "/usr/share/other-empty", SHA256: fixtureDigest(nil), Component: fixtureComponent("pm"), Kind: "pm"})
		}
		bom := cdx.NewBOM()
		err := Verify(context.Background(), fixtureImage(map[string][]byte{name: nil}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, Originals: originals})
		if !own {
			gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(name), gomega.ContainSubstring("no-data"))))
			return
		}
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", name), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "generated"}))))))
	}, ginkgo.Entry("outside user roots", "/relocated/empty", false, 1), ginkgo.Entry("inside user roots", "/src/empty", true, 1), ginkgo.Entry("several empty originals", "/src/empty", true, 2))
	ginkgo.It("retains an empty package file at its declared path", func() {
		original := Original{Path: "/usr/share/empty", SHA256: fixtureDigest(nil), Component: fixtureComponent("pm"), Kind: "pm"}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{original.Path: nil}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{original}})).To(gomega.Succeed())
	})
	ginkgo.It("keeps a nonempty package header under its package inside ownRoots", func() {
		body := []byte("package header")
		bom := cdx.NewBOM()
		original := Original{Path: "/usr/include/header.h", SHA256: fixtureDigest(body), Component: fixtureComponent("pm"), Kind: "pm"}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/header.h": body}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, Originals: []Original{original}})).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/src/header.h"), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "pm"}))))))
	})
	ginkgo.It("accounts a copy while the package original remains", func() {
		body := []byte("package data")
		bom := cdx.NewBOM()
		original := Original{Path: "/usr/share/data", SourcePath: "usr/share/data", SHA256: fixtureDigest(body), Component: fixtureComponent("pm"), Kind: "pm"}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/usr/share/data": body, "/relocated/data": body}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{original}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, name := range []string{"/usr/share/data", "/relocated/data"} {
			gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", name), gomega.HaveField("Type", cdx.ComponentTypeFile), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "pm"}))))))
		}
	})
	ginkgo.It("does not infer a moved package from a git original", func() {
		body := []byte("source data")
		original := Original{Path: "/src/data", SHA256: fixtureDigest(body), Component: fixtureComponent("git"), Kind: "git"}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/relocated/data": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{original}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/relocated/data"), gomega.ContainSubstring("no-data"))))
	})
	ginkgo.It("retains the package owner for exactly one matching original", func() {
		body := []byte("package data")
		bom := cdx.NewBOM()
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/relocated/data": body}), bom, VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: "/usr/share/data", SourcePath: "usr/share/data", SHA256: fixtureDigest(body), Component: fixtureComponent("pm"), Kind: "pm"}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.HaveField("Name", "pm")))
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/relocated/data"), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "pm"}))))))
	})
	ginkgo.It("refuses two matching files even when they belong to the same package", func() {
		body := []byte("same")
		originals := []Original{{Path: "/usr/share/one", SourcePath: "usr/share/one", SHA256: fixtureDigest(body), Component: fixtureComponent("pm"), Kind: "pm"}, {Path: "/usr/share/two", SourcePath: "usr/share/two", SHA256: fixtureDigest(body), Component: fixtureComponent("pm"), Kind: "pm"}}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/relocated/data": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: originals})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/relocated/data"), gomega.ContainSubstring("ambiguous"))))
	})
	ginkgo.It("refuses renamed content without a matching original", func() {
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/relocated/data": []byte("changed")}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: "/usr/share/data", SHA256: fixtureDigest([]byte("original")), Component: fixtureComponent("pm"), Kind: "pm"}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/relocated/data"), gomega.ContainSubstring("no-data"))))
	})
	ginkgo.It("does not reclassify a modified renamed package executable as a new build", func() {
		record := fixtureRecord("c-static", "linux/amd64")
		record["components"] = []any{map[string]any{"id": "app", "name": "package-builder", "version": "1", "source": map[string]string{"kind": "declared", "locator": "dk:image:package-builder"}}}
		original := fixtureELF(elf.ET_EXEC, record)
		changed := append(append([]byte{}, original...), []byte("changed")...)
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/relocated/tool": changed}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: "/usr/bin/tool", SHA256: fixtureDigest(original), Component: fixtureComponent("pm"), Kind: "pm"}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/relocated/tool"), gomega.ContainSubstring("no-data"))))
	})
})
