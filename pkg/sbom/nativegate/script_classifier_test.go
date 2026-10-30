package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"maps"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const (
	installedScript = "#!/bin/sh\necho installed\n"
	changedScript   = "#!/bin/sh\necho changed\n"
)

// Stage files a build marks executable, which is what makes a script look like a binary
// to a gate reading the mode instead of the content.
func executableStage(ctx context.Context, stage string, files map[string]string) (SourceSnapshot, v1.Image) {
	ginkgo.GinkgoHelper()

	return modeStage(ctx, stage, files, 0o755)
}

func plainStage(ctx context.Context, stage string, files map[string]string) (SourceSnapshot, v1.Image) {
	ginkgo.GinkgoHelper()

	return modeStage(ctx, stage, files, 0o644)
}

func modeStage(ctx context.Context, stage string, files map[string]string, mode int64) (SourceSnapshot, v1.Image) {
	ginkgo.GinkgoHelper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: mode, Size: int64(len(files[name]))})).To(gomega.Succeed())
		_, err := writer.Write([]byte(files[name]))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	layer, err := fixtureLayer(buffer.Bytes())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	index, err := shippedscope.IndexImageFiles(ctx, image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(index.Incomplete).To(gomega.BeFalse())

	return SourceSnapshot{Stage: stage, Index: index}, image
}

var _ = ginkgo.Describe("Interpreted script classification", func() {
	ginkgo.DescribeTable("reads a complete text script of a known interpreter", func(body string) {
		gomega.Expect(interpretedScript([]byte(body), "/app/run")).To(gomega.BeTrue())
	},
		ginkgo.Entry("an absolute shell interpreter", "#!/bin/sh\necho hello\n"),
		ginkgo.Entry("an interpreter with arguments", "#!/bin/bash -eu\necho hello\n"),
		ginkgo.Entry("env resolving the interpreter", "#!/usr/bin/env python3\nprint(1)\n"),
		ginkgo.Entry("env splitting its own argument", "#!/usr/bin/env -S node --no-warnings\nconsole.log(1)\n"),
		ginkgo.Entry("a body without a trailing newline", "#!/usr/bin/dash\necho hello"),
		ginkgo.Entry("non-ASCII text in the body", "#!/usr/bin/env ash\necho ≈\n"),
	)

	ginkgo.DescribeTable("leaves everything else an unknown executable", func(body, name string) {
		gomega.Expect(interpretedScript([]byte(body), name)).To(gomega.BeFalse())
	},
		ginkgo.Entry("an interpreter outside the known list", "#!/bin/shh\necho hello\n", "/app/run"),
		ginkgo.Entry("a relative interpreter", "#!sh\necho hello\n", "/app/run"),
		ginkgo.Entry("an unnormalized interpreter path", "#!/usr/bin/../bin/sh\necho hello\n", "/app/run"),
		ginkgo.Entry("a quoted interpreter", `#!/usr/bin/env "python3"`+"\nprint(1)\n", "/app/run"),
		ginkgo.Entry("env with no interpreter", "#!/usr/bin/env\necho hello\n", "/app/run"),
		ginkgo.Entry("env handed a name it cannot resolve", "#!/usr/bin/env python3 -u\nprint(1)\n", "/app/run"),
		ginkgo.Entry("env with an environment assignment", "#!/usr/bin/env -S FOO=bar python3\nprint(1)\n", "/app/run"),
		ginkgo.Entry("no shebang at all", "echo hello\n", "/app/run"),
		ginkgo.Entry("an unterminated shebang line", "#!/bin/sh", "/app/run"),
		ginkgo.Entry("a shebang line longer than the kernel reads", "#!/bin/sh -c "+strings.Repeat("x", 256)+"\necho hello\n", "/app/run"),
		ginkgo.Entry("a shebang and nothing else", "#!/bin/sh\n\n  \n", "/app/run"),
		ginkgo.Entry("a binary payload behind a shebang", "#!/bin/sh\n\x00\x01\x02binary\n", "/app/run"),
		ginkgo.Entry("an ELF payload behind a shebang", "#!/bin/sh\n\x7fELF\x02\x01\x01payload\n", "/app/run"),
		ginkgo.Entry("invalid UTF-8 in the body", "#!/bin/sh\necho \xff\xfe\n", "/app/run"),
		ginkgo.Entry("an archive opening with a shebang inside", "!<arch>\n#!/bin/sh\necho hello\n", "/app/run"),
		ginkgo.Entry("a shared object holding script text", "#!/bin/sh\necho hello\n", "/usr/lib/libfoo.so"),
	)

	ginkgo.It("records an executable script of the build as an ordinary file", func(ctx ginkgo.SpecContext) {
		from, _ := executableStage(ctx, "from", map[string]string{})
		install, image := executableStage(ctx, "install", map[string]string{"/app/run.sh": installedScript})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)).To(gomega.BeEmpty(), "an unattributed script claims no package owner")
		gomega.Expect(transportOriginals(bom).Files).To(gomega.BeEmpty())
	})

	ginkgo.DescribeTable("refuses an executable the file evidence cannot read", func(ctx ginkgo.SpecContext, body, name, expected string) {
		from, _ := executableStage(ctx, "from", map[string]string{})
		install, image := executableStage(ctx, "install", map[string]string{name: body})

		_, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("a shebang over binary content", "#!/bin/sh\n\x00\x01\x02\n", "/app/run.sh", "unsupported: unknown binary or unsupported format /app/run.sh"),
		ginkgo.Entry("an opaque executable", "\x01\x02\x03\x04 payload\n", "/app/tool", "unsupported: unknown binary or unsupported format /app/tool"),
		ginkgo.Entry("executable text with a NUL", "module.exports = 1;\x00\n", "/ui/node_modules/x/index.js", "unsupported: unknown binary or unsupported format /ui/node_modules/x/index.js"),
		ginkgo.Entry("executable text with an escape byte", "module.exports = '\x1b[0m';\n", "/ui/node_modules/x/index.js", "unsupported: unknown binary or unsupported format /ui/node_modules/x/index.js"),
		ginkgo.Entry("executable text that is not UTF-8", "module.exports = '\xc0\xaf';\n", "/ui/node_modules/x/index.js", "unsupported: unknown binary or unsupported format /ui/node_modules/x/index.js"),
		ginkgo.Entry("executable text cut inside a character", "module.exports = '\xe2\x82", "/ui/node_modules/x/index.js", "unsupported: unknown binary or unsupported format /ui/node_modules/x/index.js"),
		ginkgo.Entry("printable bytes behind a native magic", "MZprintable text\n", "/app/tool", "/app/tool: unsupported: not a selected native executable or shared object"),
		ginkgo.Entry("an archive", "!<arch>\npayload\n", "/app/tool.a", "/app/tool.a: unsupported: binary format has no embedded composition reader"),
	)

	ginkgo.DescribeTable("reads executable text without a shebang as the same text without the bit", func(ctx ginkgo.SpecContext, body string) {
		from, _ := executableStage(ctx, "from", map[string]string{})
		install, image := executableStage(ctx, "install", map[string]string{"/ui/node_modules/uri-js/dist/esnext/schemes/http.js": body})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)).To(gomega.BeEmpty(), "text claims no component")
	},
		ginkgo.Entry("a JavaScript module from an npm tarball", "import { pctEncChar } from \"../uri\";\nconst handler = { scheme: \"http\" };\nexport default handler;\n"),
		ginkgo.Entry("text behind a byte order mark", "\ufeffexport default 1;\n"),
		ginkgo.Entry("text with tabs, carriage returns and form feeds", "a\tb\r\n\fc\n"),
		ginkgo.Entry("non-ASCII text", "export const quote = '≈';\n"),
		ginkgo.Entry("a script whose interpreter is misspelled", "#!/bin/bsah\necho hello\n"),
	)

	ginkgo.DescribeTable("accepts an empty file whatever its mode or name", func(ctx ginkgo.SpecContext, name string) {
		from, _ := executableStage(ctx, "from", map[string]string{})
		install, image := executableStage(ctx, "install", map[string]string{name: ""})

		_, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	},
		ginkgo.Entry("the file a container runtime leaves behind", "/.dockerenv"),
		ginkgo.Entry("an empty shared object", "/usr/lib/libempty.so"),
	)

	ginkgo.It("still refuses a one-byte executable", func(ctx ginkgo.SpecContext) {
		from, _ := executableStage(ctx, "from", map[string]string{})
		install, image := executableStage(ctx, "install", map[string]string{"/.dockerenv": "\x01"})

		_, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported: unknown binary or unsupported format /.dockerenv")))
	})

	ginkgo.It("keeps the package owner of an installed script the build did not touch", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/bin/tool.sh": installedScript})

		from, _ := executableStage(ctx, "from", map[string]string{})
		packages, _ := executableStage(ctx, "packages", map[string]string{"/usr/bin/tool.sh": installedScript})
		packages.Receipt = transportReceipt(source)
		install, image := executableStage(ctx, "install", map[string]string{"/usr/bin/tool.sh": installedScript, "/app/run.sh": "#!/usr/bin/env bash\necho built here\n"})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		records := transportRecords(bom)
		gomega.Expect(slices.Sorted(maps.Keys(records))).To(gomega.Equal([]string{"/usr/bin/tool.sh"}))
		gomega.Expect(records["/usr/bin/tool.sh"].Origin).To(gomega.Equal("pm"))
		gomega.Expect(records["/usr/bin/tool.sh"].SHA256).To(gomega.Equal(digest([]byte(installedScript))))
	})

	ginkgo.It("refuses a script whose installed content the build changed", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/bin/tool.sh": installedScript})

		from, _ := executableStage(ctx, "from", map[string]string{})
		packages, _ := executableStage(ctx, "packages", map[string]string{"/usr/bin/tool.sh": installedScript})
		packages.Receipt = transportReceipt(source)
		install, image := executableStage(ctx, "install", map[string]string{"/usr/bin/tool.sh": changedScript})

		_, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch: /usr/bin/tool.sh no longer holds the content its original source bound there")))
	})

	ginkgo.It("refuses a non-executable file whose installed content the build changed", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/etc/tool.conf": "key = installed\n"})

		from, _ := plainStage(ctx, "from", map[string]string{})
		packages, _ := plainStage(ctx, "packages", map[string]string{"/etc/tool.conf": "key = installed\n"})
		packages.Receipt = transportReceipt(source)
		install, image := plainStage(ctx, "install", map[string]string{"/etc/tool.conf": "key = changed\n"})

		_, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch: /etc/tool.conf no longer holds the content its original source bound there")))
	})

	ginkgo.It("keeps a non-executable installed file the build did not touch", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/etc/tool.conf": "key = installed\n"})

		from, _ := plainStage(ctx, "from", map[string]string{})
		packages, _ := plainStage(ctx, "packages", map[string]string{"/etc/tool.conf": "key = installed\n"})
		packages.Receipt = transportReceipt(source)
		install, image := plainStage(ctx, "install", map[string]string{"/etc/tool.conf": "key = installed\n"})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)["/etc/tool.conf"].Origin).To(gomega.Equal("pm"))
	})

	ginkgo.It("asks nothing of a path the build changed and then removed", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/bin/tool.sh": installedScript})

		from, _ := executableStage(ctx, "from", map[string]string{})
		packages, _ := executableStage(ctx, "packages", map[string]string{"/usr/bin/tool.sh": installedScript})
		packages.Receipt = transportReceipt(source)
		changed, _ := executableStage(ctx, "install", map[string]string{"/usr/bin/tool.sh": changedScript})
		removed, image := executableStage(ctx, "setup", map[string]string{"/app/run.sh": installedScript})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, changed, removed}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)).To(gomega.BeEmpty())
	})
})
