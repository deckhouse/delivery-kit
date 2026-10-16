package shippedscope

import (
	"bytes"
	"debug/elf"
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

	It("holds everything when a file claims to be an ELF but cannot be parsed", func(ctx SpecContext) {
		truncated := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0}, 40)...)

		classification, err := ClassifyBinary(ctx, bytes.NewReader(truncated), int64(len(truncated)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.Go).To(Equal(VerdictUnknown))
		Expect(classification.Rust).To(Equal(VerdictUnknown))
	})

	It("finds the test main when it straddles two reads", func(ctx SpecContext) {
		// The first read covers [0, chunk+overlap); a needle crossing its far edge is
		// found only because the next read starts at chunk rather than where it ended.
		const (
			chunk       = 1 << 20
			overlap     = len(testMainSource) - 1
			sectionHead = 64 + 3*64
		)

		padding := bytes.Repeat([]byte{'x'}, chunk+overlap-sectionHead-4)
		binary := elfWithSections(map[string][]byte{
			".rodata": append(padding, []byte(testMainSource)...),
		})

		classification, err := ClassifyBinary(ctx, bytes.NewReader(binary), int64(len(binary)))
		Expect(err).NotTo(HaveOccurred())

		Expect(classification.TestBinary).To(BeTrue())
	})

	It("refuses audit data larger than the cap before reading it", func(ctx SpecContext) {
		binary := oversizedSection(elfWithSections(map[string][]byte{
			rustDepSection: auditSection(`{"packages":[{"name":"serde","version":"1.0.210","source":"crates.io"}]}`),
		}), rustDepSection)

		file, err := elf.NewFile(bytes.NewReader(binary))
		Expect(err).NotTo(HaveOccurred())
		defer file.Close()

		// A compressed section is inflated inside Data(), so the size has to be rejected
		// before the read rather than capped after it.
		_, err = runtimeCrates(file.Section(rustDepSection))
		Expect(err).To(MatchError(ContainSubstring("over the")))

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
