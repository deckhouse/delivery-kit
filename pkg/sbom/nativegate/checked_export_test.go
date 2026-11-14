package nativegate

import (
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("checked producer exports", func() {
	ginkgo.DescribeTable("refuses invalid exported files", func(ctx ginkgo.SpecContext, filename string, body []byte, originals []Original, reason string) {
		img := fixtureImage(map[string][]byte{filename: body})
		err := VerifyExport(ctx, img, cdx.NewBOM(), []string{filename}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out", "/src"}, Originals: originals})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(filename), gomega.ContainSubstring(reason))))
	},
		ginkgo.Entry("ELF without composition", "/out/tool", fixtureELF(elf.ET_EXEC, nil), []Original{}, "missing"),
		ginkgo.Entry("modified tracked text", "/src/header.h", []byte("changed"), []Original{{Path: "/src/header.h", SHA256: fixtureDigest([]byte("original")), Component: fixtureComponent("git"), Kind: "git"}}, "hash-mismatch"),
		ginkgo.Entry("stock text outside producer roots", "/usr/include/stock.h", []byte("stock"), []Original{}, "directory is not in a git mapping/WorkingDir"),
	)
	ginkgo.It("marks generated text and excludes unexported stock tools", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(map[string][]byte{"/out/config.h": []byte("generated"), "/usr/bin/stock": fixtureELF(elf.ET_EXEC, nil)})
		bom := cdx.NewBOM()
		gomega.Expect(VerifyExport(ctx, img, bom, []string{"/out/config.h"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}})).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/out/config.h"), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "generated"}))))))
		gomega.Expect(*bom.Components).NotTo(gomega.ContainElement(gomega.HaveField("Name", "/usr/bin/stock")))
		_, err := ImageOriginals(ctx, bom, "linux/amd64")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unverified")))
	})
	ginkgo.It("refuses a missing selected export instead of succeeding with no files", func(ctx ginkgo.SpecContext) {
		err := VerifyExport(ctx, fixtureImage(nil), cdx.NewBOM(), []string{"/out/missing"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/out/missing")))
	})
})
