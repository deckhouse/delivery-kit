package shippedscope

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"slices"

	"github.com/werf/logboek"
)

// Verdict is what a binary says about the components of one ecosystem.
type Verdict string

const (
	// VerdictNone — the binary is not of that ecosystem and holds none of its components.
	VerdictNone Verdict = "none"
	// VerdictNames — the binary says which components it carries, and holds only those.
	VerdictNames Verdict = "names"
	// VerdictUnknown — the binary could carry components of that ecosystem but names
	// none, so every one of them is held. "I don't know" is never "not shipped".
	VerdictUnknown Verdict = "unknown"
)

type Crate struct {
	Name    string
	Version string
}

// BinaryClassification is what one produced file says about the components compiled into
// it. A Go module and a Rust crate keep no files of their own in an image — the binary is
// the only place that knows they are there.
type BinaryClassification struct {
	// TestBinary marks a binary `go test -c` produced. It carries the test's dependencies
	// and ships with nothing, so it speaks for no component at all.
	TestBinary bool

	Go Verdict
	// Modules holds module paths, never versions: the build info of a binary describes
	// go.mod as it was when the binary was linked, and the SBOM describes go.mod as it is
	// now. Matching on version would turn that skew into a lost component.
	Modules []string

	Rust   Verdict
	Crates []Crate
}

const (
	// Two marks together name a `go test -c` binary. The generated main's source path
	// alone is not enough: the `go` tool carries it as the literal it writes that file
	// with. The test runner's own function is not enough either: a binary embedding a
	// test framework can reach it. Only a binary that both generates a test main and
	// runs it is a test binary.
	testMainSource = "_testmain.go"
	testRunnerFunc = "testing.tRunner"
	// The section cargo-auditable writes, holding zlib-compressed JSON.
	rustDepSection    = ".dep-v0"
	cgoEnabledSetting = "CGO_ENABLED"
)

// binaryFormat is an executable container a binary can describe itself in. A Linux image
// is not only ELF: an image whose product is a release archive ships the binaries its
// users download, built for every platform the project supports.
type binaryFormat string

const (
	formatELF   binaryFormat = "ELF"
	formatMachO binaryFormat = "Mach-O"
	formatPE    binaryFormat = "PE"
	formatWasm  binaryFormat = "wasm"
)

// goFormatSections name a Go binary of a format even when its build info is gone. A
// format missing here carries no such mark, so nothing in it can rule Go out.
var goFormatSections = map[binaryFormat][]string{
	formatELF:   {".gopclntab", ".go.buildinfo"},
	formatMachO: {"__gopclntab", "__go_buildinfo"},
}

var formatMagic = map[binaryFormat][][]byte{
	formatELF:  {{0x7f, 'E', 'L', 'F'}},
	formatWasm: {{0x00, 'a', 's', 'm'}},
	formatMachO: {
		{0xfe, 0xed, 0xfa, 0xce},
		{0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe},
		{0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe},
		{0xbe, 0xba, 0xfe, 0xca},
		{0xca, 0xfe, 0xba, 0xbf},
		{0xbf, 0xba, 0xfe, 0xca},
	},
	formatPE: {{'M', 'Z'}},
}

// binaryImage is as much of a binary's own structure as the rule needs: the sections it
// reads evidence out of, and the format that says what a missing section means.
type binaryImage struct {
	format   binaryFormat
	sections map[string]binarySection
}

// binarySection carries the recorded size beside the content, so a section claiming more
// than the reader accepts is refused before a decompressor is pointed at it.
type binarySection struct {
	size uint64
	data func() ([]byte, error)
}

// ClassifyBinary answers which components a produced binary carries, reading only the
// binary's own metadata.
//
// The branches are ordered, and the order is the point. A test binary is recognized first:
// it is nothing but dependencies, and `go test -c` leaves no mark in the build info — not
// in the path, and not in an empty dependency list, since a test binary inherits whatever
// the package under test imports. Build info that was wiped comes next, because an
// obfuscator leaves an empty dependency list behind on a binary whose dependencies are
// alive; reading that as knowledge would drop every one of them.
//
// Go and Rust are read independently: a cgo binary linking an audited Rust archive carries
// the evidence of both, and an early return on either would drop the other.
//
// Unreadable executable containers hold all dependencies. Universal Mach-O containers
// also fail open: the thin-file parser cannot establish what every architecture carries.
// Only ELF and thin Mach-O section tables can rule Go out without readable build info.
func ClassifyBinary(ctx context.Context, binary io.ReaderAt, size int64) (BinaryClassification, error) {
	none := BinaryClassification{Go: VerdictNone, Rust: VerdictNone}
	unknown := BinaryClassification{Go: VerdictUnknown, Rust: VerdictUnknown}

	if size <= 0 {
		return unknown, fmt.Errorf("classify binary: size is %d", size)
	}

	format, executable, err := formatOf(binary)
	if err != nil {
		return unknown, fmt.Errorf("classify binary: %w", err)
	}
	if !executable {
		return none, nil
	}

	sections, err := sectionsOf(format, binary)
	if err != nil {
		logboek.Context(ctx).Debug().LogF("parse %s: %s\n", format, err)

		return unknown, nil
	}
	image := binaryImage{format: format, sections: sections}

	if image.mayBeGo() {
		// Only a Go binary can be a test binary, and the scan reads the file end to end:
		// running it on every shared library in an image would cost seconds per image. A
		// binary with no section headers at all is scanned regardless, since nothing
		// there says whether it is Go.
		testBinary, err := carriesTestMarks(binary, size)
		if err != nil {
			return unknown, fmt.Errorf("classify binary: %w", err)
		}
		if testBinary {
			classification := none
			classification.TestBinary = true

			return classification, nil
		}
	}

	info, err := buildinfo.Read(binary)

	classification := none
	classification.Go, classification.Modules = goEvidenceOf(ctx, image, info, err)
	classification.Rust, classification.Crates = rustEvidence(ctx, image, info)

	return classification, nil
}

func formatOf(binary io.ReaderAt) (binaryFormat, bool, error) {
	header := make([]byte, 4)

	read, err := binary.ReadAt(header, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, fmt.Errorf("read binary header: %w", err)
	}
	header = header[:read]

	for format, magics := range formatMagic {
		for _, magic := range magics {
			if bytes.HasPrefix(header, magic) {
				return format, true, nil
			}
		}
	}

	return "", false, nil
}

func sectionsOf(format binaryFormat, binary io.ReaderAt) (map[string]binarySection, error) {
	sections := make(map[string]binarySection)

	switch format {
	case formatELF:
		file, err := elf.NewFile(binary)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		for _, section := range file.Sections {
			sections[section.Name] = binarySection{size: section.Size, data: section.Data}
		}
	case formatMachO:
		file, err := macho.NewFile(binary)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		for _, section := range file.Sections {
			sections[section.Name] = binarySection{size: section.Size, data: section.Data}
		}
	case formatPE:
		file, err := pe.NewFile(binary)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		for _, section := range file.Sections {
			sections[section.Name] = binarySection{size: uint64(section.Size), data: section.Data}
		}
	}

	return sections, nil
}

// mayBeGo tells whether anything about the file rules Go out. Only a format with a
// section that marks a Go binary can rule it out at all; in one without, and in a binary
// whose section headers are gone, the question stays open rather than answered.
func (image binaryImage) mayBeGo() bool {
	marks, told := goFormatSections[image.format]
	if !told {
		return true
	}

	for _, name := range marks {
		if _, ok := image.sections[name]; ok {
			return true
		}
	}

	return len(image.sections) == 0
}

func goEvidenceOf(ctx context.Context, image binaryImage, info *debug.BuildInfo, err error) (Verdict, []string) {
	if err != nil {
		// Sections are what tells "not Go" from "Go I cannot read". A binary that says
		// neither holds every module rather than none.
		if image.mayBeGo() {
			logboek.Context(ctx).Debug().LogF("read Go build info: %s\n", err)

			return VerdictUnknown, nil
		}

		return VerdictNone, nil
	}

	return goEvidence(info)
}

func rustEvidence(ctx context.Context, image binaryImage, info *debug.BuildInfo) (Verdict, []Crate) {
	section, audited := image.sections[rustDepSection]
	if !audited {
		if builtWithoutCgo(info) {
			// A Go binary that links no C object carries no crate either.
			return VerdictNone, nil
		}

		// Nothing can be told about crates from a Rust binary built without cargo
		// auditable, and a binary of another language is indistinguishable from one. The
		// aggregate is blunt on purpose: one unaudited binary — a libc, a shell — makes
		// the image hold every crate. Narrowing it needs a test for "is this Rust at
		// all", which no cheap and reliable mark provides today.
		return VerdictUnknown, nil
	}

	crates, err := runtimeCrates(section)
	if err != nil {
		logboek.Context(ctx).Debug().LogF("read %s: %s\n", rustDepSection, err)

		return VerdictUnknown, nil
	}

	return VerdictNames, crates
}

// goEvidence reads the build info of a binary already known not to be a test binary.
func goEvidence(info *debug.BuildInfo) (Verdict, []string) {
	// An obfuscator leaves the module path and the settings empty while the dependency
	// list it emptied describes a binary whose dependencies are alive. GoVersion is no
	// part of the test: garble fills it with "unknown" rather than clearing it.
	if info.Path == "" && len(info.Settings) == 0 {
		return VerdictUnknown, nil
	}

	var modules []string
	for _, dep := range info.Deps {
		modules = append(modules, dep.Path)

		if dep.Replace != nil {
			modules = append(modules, dep.Replace.Path)
		}
	}

	return VerdictNames, modules
}

func builtWithoutCgo(info *debug.BuildInfo) bool {
	if info == nil {
		return false
	}

	for _, setting := range info.Settings {
		if setting.Key == cgoEnabledSetting {
			return setting.Value == "0"
		}
	}

	return false
}

// carriesTestMarks looks for both marks of a `go test -c` binary, which survive -trimpath
// and -ldflags="-s -w". The path of the testing package's own source cannot serve here:
// every binary linking the testing package carries it, production tools among them, and a
// tool misread as a test binary would hold no component at all.
//
// Both marks are needed because each has a witness that carries it alone. The `go` tool
// writes the generated main's path as a literal, so requiring it alone would make a
// shipped Go toolchain hold nothing; a binary embedding a test framework can reach the
// runner's own function without ever being a test.
func carriesTestMarks(binary io.ReaderAt, size int64) (bool, error) {
	const chunk = 1 << 20

	needles := [][]byte{[]byte(testMainSource), []byte(testRunnerFunc)}

	// A match split across two reads is found by overlapping them.
	overlap := 0
	for _, needle := range needles {
		overlap = max(overlap, len(needle)-1)
	}

	found := make([]bool, len(needles))
	buffer := make([]byte, chunk+overlap)

	for offset := int64(0); offset < size; offset += chunk {
		read, err := binary.ReadAt(buffer, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return false, fmt.Errorf("read binary at %d: %w", offset, err)
		}

		for i, needle := range needles {
			found[i] = found[i] || bytes.Contains(buffer[:read], needle)
		}

		if !slices.Contains(found, false) {
			return true, nil
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	return false, nil
}

// auditData is what cargo auditable records: the crates of the build, each marked with the
// kind of dependency it was.
type auditData struct {
	Packages []auditPackage `json:"packages"`
}

type auditPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Kind is absent for a runtime dependency — the serialiser omits its default — so
	// anything that is not a build dependency ships with the binary.
	Kind string `json:"kind"`
}

const (
	buildDependency = "build"
	maxAuditData    = 8 << 20
)

func runtimeCrates(section binarySection) ([]Crate, error) {
	// Audit data of a real binary is tens of kilobytes. The size is checked before the
	// section is read because debug/elf inflates a compressed section inside Data().
	if section.size > maxAuditData {
		return nil, fmt.Errorf("section is %d bytes, over the %d limit", section.size, maxAuditData)
	}

	compressed, err := section.data()
	if err != nil {
		return nil, fmt.Errorf("read section: %w", err)
	}

	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	defer reader.Close()

	// The stored size says nothing about the inflated one, so the inflated side is
	// capped too, and reading one byte past the cap tells a bomb from data that fits.
	data, err := io.ReadAll(io.LimitReader(reader, maxAuditData+1))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	if len(data) > maxAuditData {
		return nil, fmt.Errorf("audit data inflates over the %d limit", maxAuditData)
	}

	var audit auditData
	if err := json.Unmarshal(data, &audit); err != nil {
		return nil, fmt.Errorf("parse audit data: %w", err)
	}

	var crates []Crate
	for _, pkg := range audit.Packages {
		if pkg.Kind == buildDependency {
			continue
		}

		crates = append(crates, Crate{Name: pkg.Name, Version: pkg.Version})
	}

	return crates, nil
}
