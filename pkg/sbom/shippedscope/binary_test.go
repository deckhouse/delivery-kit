package shippedscope

import (
	"bytes"
	"runtime/debug"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ClassifyBinary, build info", func() {
	It("holds the modules the linker put in, by path and never by version", func() {
		verdict, modules := goEvidence(&debug.BuildInfo{
			GoVersion: "go1.24.9",
			Path:      "example.test/app",
			Deps: []*debug.Module{
				{Path: "github.com/spf13/cobra", Version: "v1.8.0"},
				{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"},
			},
		})

		Expect(verdict).To(Equal(VerdictNames))
		Expect(modules).To(Equal([]string{"github.com/spf13/cobra", "gopkg.in/yaml.v3"}))
	})

	It("holds both sides of a replace, so a fork answers under either path", func() {
		verdict, modules := goEvidence(&debug.BuildInfo{
			GoVersion: "go1.24.9",
			Path:      "example.test/app",
			Deps: []*debug.Module{
				{
					Path:    "github.com/spf13/cobra",
					Version: "v1.8.0",
					Replace: &debug.Module{Path: "github.com/werf/3p-cobra", Version: "v1.8.1"},
				},
			},
		})

		Expect(verdict).To(Equal(VerdictNames))
		Expect(modules).To(ContainElements("github.com/spf13/cobra", "github.com/werf/3p-cobra"))
	})

	It("holds nothing for a binary that linked no dependency", func() {
		verdict, modules := goEvidence(&debug.BuildInfo{
			GoVersion: "go1.24.9",
			Path:      "example.test/app",
			Settings:  []debug.BuildSetting{{Key: "GOARCH", Value: "amd64"}},
		})

		Expect(verdict).To(Equal(VerdictNames))
		Expect(modules).To(BeEmpty())
	})

	It("holds everything when the build info was wiped, empty dependencies and all", func() {
		verdict, modules := goEvidence(&debug.BuildInfo{})

		Expect(verdict).To(Equal(VerdictUnknown))
		Expect(modules).To(BeEmpty())
	})

	It("holds everything when an obfuscator left a version string behind", func() {
		// What garble actually emits: it fills GoVersion rather than clearing it.
		verdict, modules := goEvidence(&debug.BuildInfo{GoVersion: "unknown"})

		Expect(verdict).To(Equal(VerdictUnknown))
		Expect(modules).To(BeEmpty())
	})
})

var _ = DescribeTable("ClassifyBinary, crates of a Go binary",
	func(settings []debug.BuildSetting, expected bool) {
		Expect(builtWithoutCgo(&debug.BuildInfo{Settings: settings})).To(Equal(expected))
	},
	Entry("a binary linking no C object carries no crate",
		[]debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}}, true),
	Entry("a cgo binary may link an audit-less Rust archive",
		[]debug.BuildSetting{{Key: "CGO_ENABLED", Value: "1"}}, false),
	Entry("build info that does not say leaves it open",
		[]debug.BuildSetting{{Key: "GOARCH", Value: "amd64"}}, false),
)

var _ = DescribeTable("ClassifyBinary, what a format can rule out",
	func(format binaryFormat, names []string, expected bool) {
		sections := make(map[string]binarySection, len(names))
		for _, name := range names {
			sections[name] = binarySection{}
		}

		Expect(binaryImage{format: format, sections: sections}.mayBeGo()).To(Equal(expected))
	},
	Entry("an ELF of another language says so", formatELF, []string{".text", ".rodata"}, false),
	Entry("an ELF carrying the Go runtime's table says so too", formatELF, []string{".text", ".gopclntab"}, true),
	Entry("a Mach-O of another language says so", formatMachO, []string{"__text", "__rodata"}, false),
	Entry("a Mach-O carrying the Go runtime's table says so too", formatMachO, []string{"__text", "__gopclntab"}, true),
	Entry("a PE carries no mark either way", formatPE, []string{".text", ".rdata"}, true),
	Entry("a wasm module has no sections to read", formatWasm, nil, true),
	Entry("a binary stripped of its section headers says neither", formatELF, nil, true),
)

var _ = Describe("ClassifyBinary", func() {
	It("reads the modules of a Go binary", func(ctx SpecContext) {
		binary := goBinary()

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeFalse())
		Expect(classification.Go).To(Equal(VerdictNames))
		Expect(classification.Modules).To(ContainElement("example.test/lib"))
		Expect(classification.Rust).To(Equal(VerdictNone))
	})

	DescribeTable("reads the modules of a binary built for another platform",
		func(ctx SpecContext, platform string) {
			binary := goBinaryFor(platform)

			classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
			Expect(err).NotTo(HaveOccurred())

			Expect(classification.Go).To(Equal(VerdictNames))
			Expect(classification.Modules).To(ContainElement("example.test/lib"),
				"an image shipping a release archive carries binaries it cannot run itself")
		},
		Entry("Mach-O", "darwin/arm64"),
		Entry("PE", "windows/amd64"),
	)

	It("holds every module of a wasm binary, which nothing here can read", func(ctx SpecContext) {
		binary := goBinaryFor("js/wasm")

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictUnknown),
			"debug/buildinfo does not read wasm, and an unreadable module holds its modules rather than losing them")
	})

	It("speaks for nobody when the file is in no executable format at all", func(ctx SpecContext) {
		document := []byte("#!/bin/sh\necho not a binary\n")

		classification, err := ClassifyBinary(ctx, bytes.NewReader(document), int64(len(document)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictNone))
		Expect(classification.Rust).To(Equal(VerdictNone))
	})

	It("lets a test binary speak for nobody, however alive its dependencies are", func(ctx SpecContext) {
		binary := goTestBinary()

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeTrue())
		Expect(classification.Go).To(Equal(VerdictNone))
		Expect(classification.Modules).To(BeEmpty())
	})

	It("holds every crate the audit data calls a runtime dependency", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			rustDepSection: auditSection(`{"packages":[
				{"name":"rsapp","version":"0.1.0","source":"local","root":true},
				{"name":"serde","version":"1.0.210","source":"crates.io"},
				{"name":"anyhow","version":"1.0.89","source":"crates.io","kind":"runtime"},
				{"name":"cc","version":"1.1.0","source":"crates.io","kind":"build"}
			]}`),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Rust).To(Equal(VerdictNames))
		Expect(classification.Crates).To(Equal([]Crate{
			{Name: "rsapp", Version: "0.1.0"},
			{Name: "serde", Version: "1.0.210"},
			{Name: "anyhow", Version: "1.0.89"},
		}))
		Expect(classification.Go).To(Equal(VerdictNone))
	})

	It("lets a tool that merely links the testing package keep its modules", func(ctx SpecContext) {
		binary := goTestingLinkedBinary()

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeFalse())
		Expect(classification.Go).To(Equal(VerdictNames))
		Expect(classification.Modules).To(ContainElement("example.test/lib"))
	})

	It("reads both ecosystems of a binary that carries evidence of each", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			rustDepSection: auditSection(`{"packages":[{"name":"serde","version":"1.0.210","source":"crates.io"}]}`),
			".gopclntab":   []byte("a Go binary whose build info cannot be read"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Rust).To(Equal(VerdictNames))
		Expect(classification.Crates).To(Equal([]Crate{{Name: "serde", Version: "1.0.210"}}))
		Expect(classification.Go).To(Equal(VerdictUnknown))
	})

	It("lets the go tool keep its modules although it names the file it generates", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			".gopclntab": []byte("go"),
			".rodata":    []byte("cmd/go writes " + testMainSource + " and never runs it"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeFalse())
	})

	It("lets a binary embedding a test framework keep its modules", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			".gopclntab": []byte("go"),
			".rodata":    []byte("a framework reaching " + testRunnerFunc + " from its own main"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeFalse())
	})

	It("holds every module of a binary whose section headers are gone", func(ctx SpecContext) {
		binary := withoutSectionHeaders(elfWithSections(map[string][]byte{
			".rodata": []byte("packed"),
		}))

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictUnknown))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("still recognizes a test binary whose section headers are gone", func(ctx SpecContext) {
		binary := withoutSectionHeaders(elfWithSections(map[string][]byte{
			".rodata": []byte(testMainSource + " " + testRunnerFunc),
		}))

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeTrue())
	})

	It("refuses a size it cannot scan", func(ctx SpecContext) {
		binary := goBinary()

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), 0)
		Expect(err).To(MatchError(ContainSubstring("size is 0")))

		Expect(classification.Go).To(Equal(VerdictUnknown))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("does not read a binary of another language as a test binary", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			".rodata": []byte("a C binary quoting _testmain.go for its own reasons"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeFalse())
		Expect(classification.Go).To(Equal(VerdictNone))
	})

	It("holds everything when a file claims to be an ELF but cannot be parsed", func(ctx SpecContext) {
		truncated := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 40)...)

		classification, err := ClassifyBinary(ctx, bytes.NewReader(truncated), int64(len(truncated)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictUnknown))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	DescribeTable("finds the test main however it straddles the reads",
		func(ctx SpecContext, position func(chunk, overlap int) int) {
			const chunk = 1 << 20

			overlap := len(testMainSource) - 1
			binary := elfWithTestMainAt(position(chunk, overlap))

			classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
			Expect(err).NotTo(HaveOccurred())

			Expect(classification.TestBinary).To(BeTrue())
		},
		// Crossing the stride is caught only by the buffer being longer than the stride.
		Entry("across the stride boundary", func(chunk, _ int) int { return chunk - 4 }),
		// Crossing the far edge of a read is caught only by the next read starting back
		// at the stride rather than where the previous one ended.
		Entry("across the far edge of the first read", func(chunk, overlap int) int { return chunk + overlap - 4 }),
	)

	It("refuses audit data whose stored size is over the cap before reading it", func(ctx SpecContext) {
		binary := oversizedSection(elfWithSections(map[string][]byte{
			rustDepSection: auditSection(`{"packages":[{"name":"serde","version":"1.0.210","source":"crates.io"}]}`),
		}), rustDepSection)

		sections, err := sectionsOf(formatELF, bytes.NewReader(binary))
		Expect(err).NotTo(HaveOccurred())

		_, err = runtimeCrates(sections[rustDepSection])
		Expect(err).To(MatchError(ContainSubstring("over the")))

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("refuses audit data that inflates over the cap, however small it is stored", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			rustDepSection: inflatingAuditSection(),
		})

		sections, err := sectionsOf(formatELF, bytes.NewReader(binary))
		Expect(err).NotTo(HaveOccurred())
		Expect(sections[rustDepSection].size).To(BeNumerically("<", maxAuditData))

		_, err = runtimeCrates(sections[rustDepSection])
		Expect(err).To(MatchError(ContainSubstring("inflates over the")))

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("holds everything when the binary cannot be read", func(ctx SpecContext) {
		binary := goBinary()

		classification, err := ClassifyBinary(ctx, failingReaderAt{ReaderAt: bytes.NewReader(binary), failLargerThan: 1 << 19}, int64(len(binary)))
		Expect(err).To(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictUnknown))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("holds every crate when the audit data cannot be read", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			rustDepSection: []byte("not a zlib stream"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Rust).To(Equal(VerdictUnknown))
		Expect(classification.Crates).To(BeEmpty())
	})

	It("holds every module of a Go binary whose build info is unreadable", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			".gopclntab": []byte("stripped of its build info"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictUnknown))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("holds no Go module for a binary of another language, and every crate for want of audit data", func(ctx SpecContext) {
		binary := elfWithSections(map[string][]byte{
			".rodata": []byte("a C binary"),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictNone))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("speaks for nobody when the file is not a binary at all", func(ctx SpecContext) {
		script := []byte("#!/bin/sh\necho hi\n")

		classification, err := ClassifyBinary(ctx, bytes.NewReader(script), int64(len(script)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeFalse())
		Expect(classification.Go).To(Equal(VerdictNone))
		Expect(classification.Rust).To(Equal(VerdictNone))
	})
})
