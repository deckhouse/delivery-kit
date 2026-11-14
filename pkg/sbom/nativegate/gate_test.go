package nativegate

import (
	"context"
	"debug/elf"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestNativeGate(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Native SBOM verification")
}

var _ = ginkgo.Describe("increment 1 verification", func() {
	var opts VerifyOptions
	ginkgo.BeforeEach(func() {
		opts = VerifyOptions{Platform: "linux/amd64", Subject: "app", UserRoots: []string{"/src", "/build"}}
	})

	ginkgo.DescribeTable("rejects missing composition by content regardless of filename", func(name string, kind elf.Type) {
		body := fixtureELF(kind, nil)
		err := Verify(context.Background(), fixtureImage(map[string][]byte{name: body}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(name), gomega.ContainSubstring("missing build record"))))
	},
		ginkgo.Entry("extensionless executable", "/src/tool", elf.ET_EXEC),
		ginkgo.Entry("object disguised as text", "/src/readme.txt", elf.ET_REL),
		ginkgo.Entry("library disguised as source", "/build/library.c", elf.ET_DYN),
	)

	ginkgo.It("accepts an instrumented ELF and publishes its component", func() {
		bom := cdx.NewBOM()
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/build/app": fixtureELF(elf.ET_EXEC, fixtureRecord("c-static", "linux/amd64"))}), bom, opts)).To(gomega.Succeed())
		gomega.Expect(bom.Components).NotTo(gomega.BeNil())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.HaveField("Name", "app")))
	})

	ginkgo.DescribeTable("rejects unsupported profiles", func(profile string) {
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/build/app": fixtureELF(elf.ET_EXEC, fixtureRecord(profile, "linux/amd64"))}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/build/app"), gomega.ContainSubstring("unsupported"))))
	}, ginkgo.Entry("LTO", "c-lto"), ginkgo.Entry("split debug", "c-split-debug"), ginkgo.Entry("compare debug", "c-compare-debug"), ginkgo.Entry("Rust", "rust"))

	ginkgo.It("rejects a foreign arm64 binary with its filename", func() {
		body := fixtureELF(elf.ET_EXEC, fixtureRecord("c-static", "linux/arm64"))
		body[18], body[19] = byte(elf.EM_AARCH64), 0
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/build/foreign": body}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/build/foreign"), gomega.ContainSubstring("platform"))))
	})

	ginkgo.It("rejects a platform outside the supported Linux targets", func() {
		opts.Platform = "windows/amd64"
		gomega.Expect(Verify(context.Background(), fixtureImage(nil), cdx.NewBOM(), opts)).To(gomega.MatchError(gomega.ContainSubstring("unsupported platform")))
	})

	ginkgo.DescribeTable("rejects a changed trusted file before treating it as generated", func(origin string) {
		opts.Originals = []Original{{Path: "/src/input.c", SHA256: fixtureDigest([]byte("original")), Component: fixtureComponent(origin), Kind: origin}}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/input.c": []byte("original")}), cdx.NewBOM(), opts)).To(gomega.Succeed())
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/src/input.c": []byte("changed in shell")}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src/input.c"), gomega.ContainSubstring("hash-mismatch"))))
	}, ginkgo.Entry("commit", "git"), ginkgo.Entry("installed package", "pm"), ginkgo.Entry("image import", "image"))

	ginkgo.It("marks new user files generated without claiming verification", func() {
		bom := cdx.NewBOM()
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/config.h": []byte("generated")}), bom, opts)).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "app"), gomega.HaveField("Properties", gomega.PointTo(gomega.ContainElement(cdx.Property{Name: "dk:verification", Value: "generated"}))))))
	})

	ginkgo.It("does not accept a sibling directory as user code", func() {
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/src-other/input.c": []byte("unknown")}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src-other/input.c"), gomega.ContainSubstring("no-data"))))
	})

	ginkgo.It("rejects an uninstrumented package even when the bytes match", func() {
		opts.Originals = []Original{{Path: "/usr/lib/lib.a", SHA256: fixtureDigest([]byte("unknown package")), Component: cdx.Component{Name: "outside-index"}, Kind: "pm"}}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/usr/lib/lib.a": []byte("unknown package")}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/usr/lib/lib.a"), gomega.ContainSubstring("no-data"))))
	})

	ginkgo.DescribeTable("requires SBOM from every image source", func(kind string) {
		err := ValidateImageSource(context.Background(), "/usr/bin/imported", kind, cdx.NewBOM(), "linux/amd64")
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/usr/bin/imported"), gomega.ContainSubstring("SBOM"))))
	}, ginkgo.Entry("base", "base"), ginkgo.Entry("import", "import"))

	ginkgo.It("rejects an unknown linked package in embedded composition", func() {
		record := fixtureRecord("c-static", "linux/amd64")
		record["components"] = []any{map[string]any{"id": "app", "name": "app", "version": "1", "source": map[string]string{"kind": "declared", "locator": "https://example.invalid/app"}}, map[string]any{"id": "unknown", "name": "unknown", "version": "1", "source": map[string]string{"kind": "pm", "locator": "registry.example.invalid/packages", "checksum": "sha256:" + strings.Repeat("2", 64)}}}
		record["inputs"] = []any{map[string]any{"kind": "header", "path": "/usr/include/unknown.h", "sha256": "sha256:" + strings.Repeat("3", 64), "disposition": "included", "components": []string{"unknown"}}}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/build/app": fixtureELF(elf.ET_EXEC, record)}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/build/app"), gomega.ContainSubstring("unknown"))))
	})
})
