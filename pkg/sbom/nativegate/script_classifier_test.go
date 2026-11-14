package nativegate

import (
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("tracked shebang sources", func() {
	ginkgo.It("refuses a binary payload in a non-executable shebang file", func(ctx ginkgo.SpecContext) {
		body := []byte("#!/bin/sh\ntext\x00data")
		name := "/src/script.sh"
		err := Verify(ctx, fixtureImageWithFileMode(name, body, 0o644), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: name, SHA256: fixtureDigest(body), Kind: "git", Component: fixtureComponent("git")}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(name), gomega.ContainSubstring("unsupported binary format"))))
	})
	ginkgo.DescribeTable("accepts text scripts with control characters after checking Git bytes", func(ctx ginkgo.SpecContext, body []byte) {
		name := "/src/script"
		opts := VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: name, SHA256: fixtureDigest(body), Kind: "git", Component: fixtureComponent("git")}}}
		bom := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImageWithFileMode(name, body, 0o755), bom, opts)).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", name), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "git"}))))))
		changed := append(append([]byte{}, body...), []byte("# changed\n")...)
		gomega.Expect(Verify(ctx, fixtureImageWithFileMode(name, changed, 0o755), cdx.NewBOM(), opts)).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(name), gomega.ContainSubstring("hash-mismatch"))))
	}, ginkgo.Entry("shell BEL", []byte("#!/bin/sh\necho hi\a\n")), ginkgo.Entry("Perl control bytes", []byte("#!/usr/bin/perl\n# control \x01\x1b\nprint 1;\n")))
	ginkgo.DescribeTable("refuses binary bodies even with a script name or shebang", func(ctx ginkgo.SpecContext, body []byte, reason string) {
		name := "/src/script.sh"
		err := Verify(ctx, fixtureImageWithFileMode(name, body, 0o755), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: name, SHA256: fixtureDigest(body), Kind: "git", Component: fixtureComponent("git")}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(name), gomega.ContainSubstring(reason))))
	}, ginkgo.Entry("ELF magic first", fixtureELF(elf.ET_EXEC, nil), "missing sbom metadata"),
		ginkgo.Entry("ELF after shebang", append([]byte("#!/bin/sh\n"), fixtureELF(elf.ET_EXEC, nil)...), "unsupported binary format"),
		ginkgo.Entry("NUL after shebang", []byte("#!/bin/sh\ntext\x00data"), "unsupported binary format"),
		ginkgo.Entry("invalid UTF8 after shebang", []byte("#!/bin/sh\ntext\xff"), "unsupported binary format"),
		ginkgo.Entry("DEL and ELF marker after shebang", []byte("#!/bin/sh\n\x7fELF"), "unsupported binary format"),
		ginkgo.Entry("control bytes without shebang", []byte("text\a\n"), "unsupported binary format"))
})
