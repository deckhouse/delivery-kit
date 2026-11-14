package nativegate

import (
	"debug/elf"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("checked producer exports", func() {
	ginkgo.DescribeTable("keeps the hardlink inode mode apart from an equal-content file", func(ctx ginkgo.SpecContext, targetMode, copyMode int64, refuse bool) {
		img := fixtureImageWithHiddenHardlinkTarget(targetMode, copyMode)
		index, err := shippedscope.IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(index.Files).NotTo(gomega.HaveKey("/tools/run"))
		gomega.Expect(index.Files["/out/run"].Digest).To(gomega.Equal(index.Files["/data/copy"].Digest))
		err = VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/run"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/run": index.Files["/out/run"].Digest}})
		if refuse {
			gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/run"), gomega.ContainSubstring("non-executable text"))))
		} else {
			gomega.Expect(err).To(gomega.Succeed())
		}
	}, ginkgo.Entry("executable hardlink and non-executable copy", int64(0o755), int64(0o644), true), ginkgo.Entry("non-executable hardlink and executable copy", int64(0o644), int64(0o755), false))
	ginkgo.It("refuses large binary generated exports without limiting known data", func(ctx ginkgo.SpecContext) {
		img := fixtureImageWithLargeFile("/out/data", []byte("data"), 0o644)
		opts := VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}}
		gomega.Expect(Verify(ctx, img, cdx.NewBOM(), opts)).To(gomega.Succeed())
		index, err := shippedscope.IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		opts.ProducedFiles = map[string]string{"/out/data": index.Files["/out/data"].Digest}
		gomega.Expect(VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/data"}, opts)).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/data"), gomega.ContainSubstring("non-executable text"))))
		opts.Originals = []Original{{Path: "/out/data", SHA256: index.Files["/out/data"].Digest, Kind: "pm", Component: fixtureComponent("pm")}}
		gomega.Expect(VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/data"}, opts)).To(gomega.Succeed())
	})
	ginkgo.DescribeTable("refuses non-text or executable generated exports", func(ctx ginkgo.SpecContext, body []byte, mode int64) {
		img := fixtureImageWithFileMode("/out/generated", body, mode)
		err := VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/generated"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/generated": fixtureDigest(body)}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/generated"), gomega.ContainSubstring("non-executable text"))))
	},
		ginkgo.Entry("binary suffix after text prefix", []byte(strings.Repeat("a", 8192)+"\x00binary"), int64(0o644)),
		ginkgo.Entry("invalid UTF8 suffix", []byte(strings.Repeat("a", 8192)+"\xff"), int64(0o644)),
		ginkgo.Entry("executable text", []byte("#!/bin/sh\necho generated\n"), int64(0o755)),
	)
	ginkgo.It("accepts generated Unicode text across reader boundaries", func(ctx ginkgo.SpecContext) {
		body := []byte(strings.Repeat("a", 4095) + "я\n")
		img := fixtureImage(map[string][]byte{"/out/generated": body})
		gomega.Expect(VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/generated"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/generated": fixtureDigest(body)}})).To(gomega.Succeed())
	})
	ginkgo.It("refuses an inherited stock symlink without an original or producing stage", func(ctx ginkgo.SpecContext) {
		err := VerifyExport(ctx, fixtureImageWithLinks(nil, map[string]string{"/out/link": "/stock/file"}), cdx.NewBOM(), []string{"/out/link"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/link"), gomega.ContainSubstring("producing stage"))))
	})
	ginkgo.It("keeps a produced symlink literal without exporting its target bytes", func(ctx ginkgo.SpecContext) {
		img := fixtureImageWithLinks(map[string][]byte{"/stock/file": []byte("unexported")}, map[string]string{"/out/link": "/stock/file"})
		bom := cdx.NewBOM()
		gomega.Expect(VerifyExport(ctx, img, bom, []string{"/out/link"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedSymlinks: map[string]string{"/out/link": "/stock/file"}})).To(gomega.Succeed())
		originals, err := ImageExportOriginals(ctx, bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.BeEmpty())
		gomega.Expect(*bom.Components).To(gomega.BeEmpty())
	})
	ginkgo.It("applies the inspection size limit only to selected outputs", func(ctx ginkgo.SpecContext) {
		img := fixtureImageWithLargeFile("/usr/bin/large", []byte("\x7fELF"), 0o755)
		opts := VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/file": fixtureDigest([]byte("generated"))}}
		gomega.Expect(VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/file"}, opts)).To(gomega.Succeed())
		err := VerifyExport(ctx, img, cdx.NewBOM(), []string{"/usr/bin/large"}, opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/usr/bin/large"), gomega.ContainSubstring("inspection limit"))))
	})
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
		gomega.Expect(VerifyExport(ctx, img, bom, []string{"/out/config.h"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/config.h": fixtureDigest([]byte("generated"))}})).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/out/config.h"), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "generated"}))))))
		gomega.Expect(*bom.Components).NotTo(gomega.ContainElement(gomega.HaveField("Name", "/usr/bin/stock")))
		_, err := ImageOriginals(ctx, bom, "linux/amd64")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unverified")))
	})
	ginkgo.It("refuses a missing selected export instead of succeeding with no files", func(ctx ginkgo.SpecContext) {
		err := VerifyExport(ctx, fixtureImage(nil), cdx.NewBOM(), []string{"/out/missing"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/out/missing")))
	})
	ginkgo.It("does not relabel inherited stock data as generated by changing WorkingDir", func(ctx ginkgo.SpecContext) {
		err := VerifyExport(ctx, fixtureImage(map[string][]byte{"/out/stock": []byte("stock")}), cdx.NewBOM(), []string{"/out/stock"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/stock"), gomega.ContainSubstring("producing stage"))))
	})
	ginkgo.It("checks tracked originals through a parent symlink before classifying an export", func(ctx ginkgo.SpecContext) {
		body := []byte("changed")
		img := fixtureImageWithLinks(map[string][]byte{"/out/header.h": body}, map[string]string{"/mapped": "/out"})
		err := VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/header.h"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/header.h": fixtureDigest(body)}, Originals: []Original{{Path: "/mapped/header.h", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/out/header.h"), gomega.ContainSubstring("hash-mismatch"))))
	})
	ginkgo.It("checks surviving tracked inputs even when they are not exported", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(map[string][]byte{"/out/generated": []byte("generated"), "/src/input.c": []byte("changed")})
		err := VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/generated"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/generated": fixtureDigest([]byte("generated"))}, Originals: []Original{{Path: "/src/input.c", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src/input.c"), gomega.ContainSubstring("hash-mismatch"))))
	})
	ginkgo.It("cannot retain a full image marker from a reused BOM", func(ctx ginkgo.SpecContext) {
		bom := cdx.NewBOM()
		bom.Metadata = &cdx.Metadata{Properties: &[]cdx.Property{{Name: "dk:verification", Value: "instrumented-v1"}, {Name: "dk:platform", Value: "linux/arm64"}}}
		gomega.Expect(VerifyExport(ctx, fixtureImage(nil), bom, []string{}, VerifyOptions{Subject: "checked", Platform: "linux/amd64"})).To(gomega.Succeed())
		gomega.Expect(ValidateImageSource(ctx, "/", "base", bom, "linux/amd64")).To(gomega.MatchError(gomega.ContainSubstring("unverified")))
	})
	ginkgo.It("checks a selected tracked symlink through its parent alias", func(ctx ginkgo.SpecContext) {
		img := fixtureImageWithLinks(map[string][]byte{}, map[string]string{"/mapped": "/out", "/out/link": "new"})
		err := VerifyExport(ctx, img, cdx.NewBOM(), []string{"/out/link"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", ExpectedSymlinks: map[string]string{"/mapped/link": "old"}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/mapped/link"), gomega.ContainSubstring("hash-mismatch"))))
	})
	ginkgo.It("transports generated exports without certifying the producer image", func(ctx ginkgo.SpecContext) {
		body := []byte("generated")
		bom := cdx.NewBOM()
		gomega.Expect(VerifyExport(ctx, fixtureImage(map[string][]byte{"/out/header.h": body}), bom, []string{"/out/header.h"}, VerifyOptions{Subject: "checked", Platform: "linux/amd64", UserRoots: []string{"/out"}, ProducedFiles: map[string]string{"/out/header.h": fixtureDigest(body)}})).To(gomega.Succeed())
		originals, err := ImageExportOriginals(ctx, bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		set := &PackageSet{}
		gomega.Expect(set.IncludeImage(ctx, bom, originals, "linux/amd64", TrustedPackages{})).NotTo(gomega.Succeed())
		gomega.Expect(set.IncludeExport(ctx, bom, originals, "linux/amd64", TrustedPackages{})).To(gomega.Succeed())
		originals[0].Path = "/usr/include/header.h"
		result := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(map[string][]byte{originals[0].Path: body}), result, VerifyOptions{Subject: "final", Platform: "linux/amd64", Originals: originals, TrustedComponents: *bom.Components})).To(gomega.Succeed())
		gomega.Expect(*result.Components).To(gomega.ContainElement(gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:verification", Value: "generated"})))))
	})
})
