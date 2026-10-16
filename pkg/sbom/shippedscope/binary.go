package shippedscope

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"

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
	// The generated main of a `go test -c` binary. Its own source path is the only mark
	// that tells a test binary from a tool that merely links the testing package.
	testMainSource = "_testmain.go"
	// The section cargo-auditable writes, holding zlib-compressed JSON.
	rustDepSection    = ".dep-v0"
	cgoEnabledSetting = "CGO_ENABLED"
)

// goSections name a Go binary even when its build info is gone.
var goSections = []string{".gopclntab", ".go.buildinfo"}

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
// A file that is not an ELF at all speaks for nobody: images here are Linux images, and a
// Go or Rust binary in one is an ELF. A file that looks like an ELF but cannot be parsed
// holds everything instead — "I cannot read this" is not "this contains nothing".
func ClassifyBinary(ctx context.Context, binary io.ReaderAt, size int64) (BinaryClassification, error) {
	none := BinaryClassification{Go: VerdictNone, Rust: VerdictNone}
	unknown := BinaryClassification{Go: VerdictUnknown, Rust: VerdictUnknown}

	elfBinary, err := looksLikeELF(binary)
	if err != nil {
		return unknown, err
	}
	if !elfBinary {
		return none, nil
	}

	file, err := elf.NewFile(binary)
	if err != nil {
		logboek.Context(ctx).Debug().LogF("parse ELF: %s\n", err)

		return unknown, nil
	}
	defer file.Close()

	if carriesGoSections(file) {
		// Only a Go binary can be a test binary, and the scan reads the file end to end:
		// running it on every shared library in an image would cost seconds per image.
		testBinary, err := carriesTestMain(binary, size)
		if err != nil {
			return unknown, err
		}
		if testBinary {
			classification := none
			classification.TestBinary = true

			return classification, nil
		}
	}

	info, err := buildinfo.Read(binary)

	classification := none
	classification.Go, classification.Modules = goEvidenceOf(ctx, file, info, err)
	classification.Rust, classification.Crates = rustEvidence(ctx, file, info)

	return classification, nil
}

func goEvidenceOf(ctx context.Context, file *elf.File, info *debug.BuildInfo, err error) (Verdict, []string) {
	if err != nil {
		if carriesGoSections(file) {
			logboek.Context(ctx).Debug().LogF("read Go build info: %s\n", err)

			return VerdictUnknown, nil
		}

		return VerdictNone, nil
	}

	return goEvidence(info)
}

func rustEvidence(ctx context.Context, file *elf.File, info *debug.BuildInfo) (Verdict, []Crate) {
	section := file.Section(rustDepSection)
	if section == nil {
		if builtWithoutCgo(info) {
			// A Go binary that links no C object carries no crate either.
			return VerdictNone, nil
		}

		// Nothing can be told about crates from a Rust binary built without cargo
		// auditable, and a binary of another language is indistinguishable from one. The
		// aggregate is blunt on purpose: one unaudited ELF — a libc, a shell — makes the
		// image hold every crate. Narrowing it needs a test for "is this Rust at all",
		// which no cheap and reliable mark provides today.
		return VerdictUnknown, nil
	}

	crates, err := runtimeCrates(section)
	if err != nil {
		logboek.Context(ctx).Debug().LogF("read %s: %s\n", rustDepSection, err)

		return VerdictUnknown, nil
	}

	return VerdictNames, crates
}

func looksLikeELF(binary io.ReaderAt) (bool, error) {
	magic := make([]byte, 4)

	read, err := binary.ReadAt(magic, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read binary header: %w", err)
	}

	return read == len(magic) && bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}), nil
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

func carriesGoSections(file *elf.File) bool {
	for _, name := range goSections {
		if file.Section(name) != nil {
			return true
		}
	}

	return false
}

// carriesTestMain looks for the source path of the main `go test -c` generates, which
// survives -trimpath and -ldflags="-s -w". The path of the testing package's own source
// cannot serve here: every binary linking the testing package carries it, production tools
// among them, and a tool misread as a test binary would hold no component at all.
//
// The mark is a string in the file, so a binary carrying the string for another reason
// reads as a test binary — the `go` tool itself does, since it has to name the file it
// generates. An image shipping the Go toolchain therefore holds no module on account of
// `go`, which is the safe direction for a build tool but worth knowing.
func carriesTestMain(binary io.ReaderAt, size int64) (bool, error) {
	const chunk = 1 << 20

	needle := []byte(testMainSource)
	// A match split across two reads is found by overlapping them.
	overlap := len(needle) - 1

	buffer := make([]byte, chunk+overlap)
	for offset := int64(0); offset < size; offset += chunk {
		read, err := binary.ReadAt(buffer, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return false, fmt.Errorf("read binary at %d: %w", offset, err)
		}

		if bytes.Contains(buffer[:read], needle) {
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

func runtimeCrates(section *elf.Section) ([]Crate, error) {
	// Audit data of a real binary is tens of kilobytes. The size is checked before the
	// section is read because debug/elf inflates a compressed section inside Data().
	if section.Size > maxAuditData {
		return nil, fmt.Errorf("section is %d bytes, over the %d limit", section.Size, maxAuditData)
	}

	compressed, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("read section: %w", err)
	}

	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, maxAuditData))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
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
