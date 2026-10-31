package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"maps"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
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
		ginkgo.Entry("an archive whose bytes hold no member", "!<arch>\npayload\n", "/app/tool.a", "/app/tool.a: invalid: the archive ends inside the header of entry 0"),
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

// The bodies are the ones a toolchain ships: /usr/lib/x86_64-linux-gnu/libc.so and the
// libgcc_s.so of gcc:13, and the AS_NEEDED stub gcc installs as libgcc_s_asneeded.so.
const (
	libcLinkerScript = "/* GNU ld script\n   Use the shared library, but some functions are only in\n" +
		"   the static library, so try that secondarily.  */\nOUTPUT_FORMAT(elf64-x86-64)\n" +
		"GROUP ( /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc_nonshared.a  AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 ) )\n"
	libgccLinkerScript = "/* GNU ld script\n   Use the shared library, but some functions are only in\n" +
		"   the static library.  */\nGROUP ( libgcc_s.so.1 -lgcc )\n"
	asNeededLinkerScript = "GROUP ( AS_NEEDED ( -lgcc_s ) )\n"
)

var _ = ginkgo.Describe("GNU ld script classification", func() {
	ginkgo.DescribeTable("reads a linker script as the text it is", func(body string) {
		gomega.Expect(linkerScript([]byte(body))).To(gomega.BeTrue())
		gomega.Expect(binaryLike([]byte(body), false, "/usr/lib/libc.so")).To(gomega.BeFalse())
	},
		ginkgo.Entry("the libc script of a glibc toolchain", libcLinkerScript),
		ginkgo.Entry("the libgcc_s script of gcc", libgccLinkerScript),
		ginkgo.Entry("the AS_NEEDED stub", asNeededLinkerScript),
		ginkgo.Entry("a bare INPUT directive", "INPUT(libfoo.so.1)\n"),
		ginkgo.Entry("a directive behind two comments", "/* one */\n/* two */\nSEARCH_DIR ( /usr/lib )\n"),
	)

	ginkgo.DescribeTable("leaves everything else alone", func(body string) {
		gomega.Expect(linkerScript([]byte(body))).To(gomega.BeFalse())
	},
		ginkgo.Entry("a directive with a byte no text holds", "GROUP ( libgcc_s.so.1 )\x00\n"),
		ginkgo.Entry("an unterminated comment", "/* GNU ld script\nGROUP ( libgcc_s.so.1 )\n"),
		ginkgo.Entry("an identifier merely opening with a directive", "GROUPING = 1\n"),
		ginkgo.Entry("AS_NEEDED standing outside the GROUP or INPUT it belongs in", "AS_NEEDED ( -lgcc_s )\n"),
		ginkgo.Entry("an INCLUDE, which names its file without parentheses", "INCLUDE (libfoo.ld)\n"),
		ginkgo.Entry("ordinary prose", "the group of files\n"),
		ginkgo.Entry("a shell script", "#!/bin/sh\necho hello\n"),
		ginkgo.Entry("an empty file", ""),
	)

	ginkgo.It("ships a linker script a prepared source collects under a library name", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		files["/usr/local/go/src/runtime/libgcc_s_asneeded.so"] = asNeededLinkerScript
		image := preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source"))

		bom, err := verifyPreparedSource(ctx, files, image, true)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)).To(gomega.HaveKey("/src/runtime/libgcc_s_asneeded.so"))
	})

	ginkgo.DescribeTable("reads a linker script of a final image as unattributed text", func(ctx ginkgo.SpecContext, body string) {
		from, _ := plainStage(ctx, "from", map[string]string{})
		install, image := plainStage(ctx, "install", map[string]string{"/usr/lib/x86_64-linux-gnu/libc.so": body})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)).To(gomega.BeEmpty(), "text claims no component")
	},
		ginkgo.Entry("the libc script", libcLinkerScript),
		ginkgo.Entry("the libgcc_s script", libgccLinkerScript),
		ginkgo.Entry("the AS_NEEDED stub", asNeededLinkerScript),
	)

	ginkgo.It("keeps the package owner of an installed linker script the build did not touch", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "libc", map[string]string{"/usr/lib/libc.so": libcLinkerScript})

		from, _ := plainStage(ctx, "from", map[string]string{})
		packages, _ := plainStage(ctx, "packages", map[string]string{"/usr/lib/libc.so": libcLinkerScript})
		packages.Receipt = transportReceipt(source)
		install, image := plainStage(ctx, "install", map[string]string{"/usr/lib/libc.so": libcLinkerScript})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)["/usr/lib/libc.so"].Origin).To(gomega.Equal("pm"))
	})

	ginkgo.DescribeTable("still refuses a library name over content no text reader can take",
		func(ctx ginkgo.SpecContext, body, expected string) {
			from, _ := plainStage(ctx, "from", map[string]string{})
			install, image := plainStage(ctx, "install", map[string]string{"/usr/lib/libfoo.so": body})

			_, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
		},
		ginkgo.Entry("a directive over bytes with a NUL", "GROUP ( libgcc_s.so.1 )\x00payload\n",
			"/usr/lib/libfoo.so: unsupported: binary format has no embedded composition reader"),
		ginkgo.Entry("opaque bytes carrying no magic", "\x01\x02\x03\x04 payload\n",
			"/usr/lib/libfoo.so: unsupported: binary format has no embedded composition reader"),
	)

	ginkgo.It("reads a shared object under the same name through the native path", func(ctx ginkgo.SpecContext) {
		library := minimalRuntimeELF(elf.ET_DYN)
		from, _ := plainStage(ctx, "from", map[string]string{})
		install, image := plainStage(ctx, "install", map[string]string{"/usr/lib/libfoo.so": string(library)})

		bom := cdx.NewBOM()
		gomega.Expect(ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
			[]SourceSnapshot{from, install}, bom, ApplySourceSnapshotsOptions{})).To(gomega.Succeed())
		record := transportRecords(bom)["/usr/lib/libfoo.so"]
		gomega.Expect(record.Origin).To(gomega.Equal("build"))
		gomega.Expect(record.Composition).NotTo(gomega.BeNil())
	})
})
