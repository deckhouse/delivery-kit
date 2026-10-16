package shippedscope

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
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
	testingSourcePath = "src/testing/testing.go"
	// The section cargo-auditable writes, holding zlib-compressed JSON.
	rustDepSection = ".dep-v0"
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
// A file that is not an ELF binary speaks for nobody: images here are Linux images, and a
// Go or Rust binary in one is an ELF.
func ClassifyBinary(ctx context.Context, binary io.ReaderAt, size int64) (BinaryClassification, error) {
	classification := BinaryClassification{Go: VerdictNone, Rust: VerdictNone}

	file, err := elf.NewFile(binary)
	if err != nil {
		return classification, nil
	}
	defer file.Close()

	testBinary, err := carriesTestingSource(binary, size)
	if err != nil {
		return classification, err
	}
	if testBinary {
		classification.TestBinary = true

		return classification, nil
	}

	if section := file.Section(rustDepSection); section != nil {
		crates, err := runtimeCrates(section)
		if err != nil {
			logboek.Context(ctx).Debug().LogF("read %s: %s\n", rustDepSection, err)
			classification.Rust = VerdictUnknown

			return classification, nil
		}

		classification.Rust = VerdictNames
		classification.Crates = crates

		return classification, nil
	}

	info, err := buildinfo.Read(binary)
	if err != nil {
		if carriesGoSections(file) {
			classification.Go = VerdictUnknown

			return classification, nil
		}

		// Not a Go binary, and no audit data: it holds no Go module, and whether it holds
		// a crate cannot be told from a Rust binary built without cargo auditable.
		classification.Rust = VerdictUnknown

		return classification, nil
	}

	classification.Go, classification.Modules = goEvidence(info)

	return classification, nil
}

// goEvidence reads the build info of a binary already known not to be a test binary.
func goEvidence(info *debug.BuildInfo) (Verdict, []string) {
	if info.GoVersion == "" && info.Path == "" && len(info.Settings) == 0 {
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

func carriesGoSections(file *elf.File) bool {
	for _, name := range goSections {
		if file.Section(name) != nil {
			return true
		}
	}

	return false
}

// carriesTestingSource looks for the path of the testing package's own source, which the
// test runner inside every `go test -c` binary carries and a strip does not touch.
func carriesTestingSource(binary io.ReaderAt, size int64) (bool, error) {
	const chunk = 1 << 20

	needle := []byte(testingSourcePath)
	// A match split across two reads is found by overlapping them.
	overlap := len(needle) - 1

	buffer := make([]byte, chunk+overlap)
	for offset := int64(0); offset < size; offset += chunk {
		read, err := binary.ReadAt(buffer, offset)
		if err != nil && err != io.EOF {
			return false, fmt.Errorf("read binary at %d: %w", offset, err)
		}

		if bytes.Contains(buffer[:read], needle) {
			return true, nil
		}

		if err == io.EOF {
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

const buildDependency = "build"

func runtimeCrates(section *elf.Section) ([]Crate, error) {
	compressed, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("read section: %w", err)
	}

	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	defer reader.Close()

	// Audit data of a real binary is tens of kilobytes; the cap keeps a crafted section
	// from being decompressed into memory without bound.
	const maxAuditData = 8 << 20

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
