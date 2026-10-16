package shippedscope

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	buildOnce     sync.Once
	builtGo       []byte
	builtTest     []byte
	builtLinkedGo []byte
	errBuild      error
)

// goBinary and goTestBinary return a Linux binary and the test binary of the same package,
// built once for the suite. They are built rather than committed because what is under
// test is how the Go toolchain of the day records itself.
func goBinary() []byte {
	buildFixtures()

	return builtGo
}

func goTestBinary() []byte {
	buildFixtures()

	return builtTest
}

// goTestingLinkedBinary is an ordinary tool that imports the testing package, as gopls,
// mockgen and werf itself do. It carries the path of the testing package's own source
// while being no test binary at all.
func goTestingLinkedBinary() []byte {
	buildFixtures()

	return builtLinkedGo
}

func buildFixtures() {
	GinkgoHelper()

	buildOnce.Do(func() {
		builtGo, builtTest, builtLinkedGo, errBuild = buildGoFixtures()
	})

	Expect(errBuild).NotTo(HaveOccurred())
}

func buildGoFixtures() ([]byte, []byte, []byte, error) {
	root, err := os.MkdirTemp("", "shippedscope-fixtures")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create fixture root: %w", err)
	}
	defer os.RemoveAll(root)

	sources := map[string]string{
		"lib/go.mod": "module example.test/lib\n\ngo 1.24\n",
		"lib/lib.go": "package lib\n\nfunc Greet() string { return \"hi\" }\n",
		"app/go.mod": "module example.test/app\n\ngo 1.24\n\nrequire example.test/lib v0.0.0\n\nreplace example.test/lib => ../lib\n",
		"app/main.go": "package main\n\nimport \"example.test/lib\"\n\n" +
			"func main() { println(lib.Greet()) }\n",
		"app/main_test.go": "package main\n\nimport (\n\t\"testing\"\n\n\t\"example.test/lib\"\n)\n\n" +
			"func TestGreet(t *testing.T) {\n\tif lib.Greet() == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n",
		"tool/go.mod": "module example.test/tool\n\ngo 1.24\n\nrequire example.test/lib v0.0.0\n\nreplace example.test/lib => ../lib\n",
		"tool/main.go": "package main\n\nimport (\n\t\"testing\"\n\n\t\"example.test/lib\"\n)\n\n" +
			"func main() {\n\ttesting.Init()\n\tprintln(lib.Greet())\n}\n",
	}
	for name, body := range sources {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, nil, nil, fmt.Errorf("create %s: %w", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return nil, nil, nil, fmt.Errorf("write %s: %w", name, err)
		}
	}

	binary := filepath.Join(root, "app.bin")
	testBinary := filepath.Join(root, "app.test")
	toolBinary := filepath.Join(root, "tool.bin")

	builds := []struct {
		module string
		args   []string
	}{
		{module: "app", args: []string{"build", "-o", binary, "."}},
		{module: "app", args: []string{"test", "-c", "-o", testBinary, "."}},
		{module: "tool", args: []string{"build", "-o", toolBinary, "."}},
	}
	for _, build := range builds {
		command := exec.Command("go", build.args...)
		command.Dir = filepath.Join(root, build.module)
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOFLAGS=-mod=mod", "CGO_ENABLED=0")

		if output, err := command.CombinedOutput(); err != nil {
			return nil, nil, nil, fmt.Errorf("go %s in %s: %w: %s", strings.Join(build.args, " "), build.module, err, output)
		}
	}

	built, err := os.ReadFile(binary)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read %s: %w", binary, err)
	}

	builtTest, err := os.ReadFile(testBinary)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read %s: %w", testBinary, err)
	}

	builtTool, err := os.ReadFile(toolBinary)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read %s: %w", toolBinary, err)
	}

	return built, builtTest, builtTool, nil
}

// failingReaderAt serves the small reads that parsing an ELF needs and fails the large
// ones the whole-file scan makes.
type failingReaderAt struct {
	io.ReaderAt

	failLargerThan int
}

func (r failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > r.failLargerThan {
		return 0, errors.New("read failed")
	}

	return r.ReaderAt.ReadAt(p, off)
}

// oversizedSection rewrites the recorded size of a section so it claims to hold more than
// the reader accepts, without the file actually carrying those bytes.
func oversizedSection(file []byte, name string) []byte {
	parsed, err := elf.NewFile(bytes.NewReader(parsedCopy(file)))
	Expect(err).NotTo(HaveOccurred())
	defer parsed.Close()

	index := -1
	for i, section := range parsed.Sections {
		if section.Name == name {
			index = i

			break
		}
	}
	Expect(index).NotTo(Equal(-1))

	const (
		headerSize        = 64
		sectionHeaderSize = 64
		sizeOffset        = 32
	)

	rewritten := parsedCopy(file)
	binary.LittleEndian.PutUint64(rewritten[headerSize+index*sectionHeaderSize+sizeOffset:], maxAuditData+1)

	return rewritten
}

func parsedCopy(file []byte) []byte {
	return append([]byte{}, file...)
}

// elfWithTestMainAt places the test-main mark at an exact offset in the file, so a spec
// can put it across a read boundary without knowing the layout of the ELF writer. The
// runner mark goes first, where no boundary reaches it.
func elfWithTestMainAt(offset int) []byte {
	sections := func(padding int) map[string][]byte {
		return map[string][]byte{
			// A test binary is a Go binary, and the scan runs only on those.
			".gopclntab": []byte(testRunnerFunc),
			".rodata":    append(bytes.Repeat([]byte{'x'}, padding), []byte(testMainSource)...),
		}
	}

	empty := elfWithSections(sections(0))
	start := bytes.Index(empty, []byte(testMainSource))
	Expect(start).NotTo(Equal(-1))
	Expect(offset).To(BeNumerically(">=", start))

	return elfWithSections(sections(offset - start))
}

// withoutSectionHeaders strips the section header table the way a packer does, leaving a
// file debug/elf still opens but that says nothing about its own language.
func withoutSectionHeaders(file []byte) []byte {
	stripped := parsedCopy(file)
	order := binary.LittleEndian
	order.PutUint64(stripped[40:], 0) // e_shoff
	order.PutUint16(stripped[60:], 0) // e_shnum
	order.PutUint16(stripped[62:], 0) // e_shstrndx

	return stripped
}

// inflatingAuditSection compresses a document whose inflated size is far over the cap
// while its stored size stays well under it.
func inflatingAuditSection() []byte {
	padding := strings.Repeat("a", maxAuditData+1)

	return auditSection(`{"packages":[{"name":"serde","version":"1.0.210","source":"crates.io"}],"pad":"` + padding + `"}`)
}

func auditSection(document string) []byte {
	var compressed bytes.Buffer

	writer := zlib.NewWriter(&compressed)
	_, err := writer.Write([]byte(document))
	Expect(err).NotTo(HaveOccurred())
	Expect(writer.Close()).To(Succeed())

	return compressed.Bytes()
}

// elfWithSections writes the smallest ELF64 that debug/elf reads: a header, the named
// sections, and the section name table. A real binary of the language under test would
// pull its whole toolchain into the suite.
func elfWithSections(sections map[string][]byte) []byte {
	const (
		headerSize        = 64
		sectionHeaderSize = 64
	)

	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names)

	var nameTable bytes.Buffer
	nameTable.WriteByte(0)

	nameOffsets := make(map[string]uint32, len(names)+1)
	for _, name := range append(slices.Clone(names), ".shstrtab") {
		nameOffsets[name] = uint32(nameTable.Len())
		nameTable.WriteString(name)
		nameTable.WriteByte(0)
	}

	// Section 0 is the mandatory null entry; the name table goes last.
	count := len(names) + 2
	body := new(bytes.Buffer)
	offsets := make(map[string]uint64, len(names))

	dataStart := uint64(headerSize + count*sectionHeaderSize)
	for _, name := range names {
		offsets[name] = dataStart + uint64(body.Len())
		body.Write(sections[name])
	}

	nameTableOffset := dataStart + uint64(body.Len())
	body.Write(nameTable.Bytes())

	header := make([]byte, headerSize)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	header[elf.EI_OSABI] = byte(elf.ELFOSABI_NONE)

	order := binary.LittleEndian
	order.PutUint16(header[16:], uint16(elf.ET_EXEC))
	order.PutUint16(header[18:], uint16(elf.EM_X86_64))
	order.PutUint32(header[20:], uint32(elf.EV_CURRENT))
	order.PutUint64(header[40:], uint64(headerSize)) // e_shoff
	order.PutUint16(header[52:], headerSize)         // e_ehsize
	order.PutUint16(header[58:], sectionHeaderSize)  // e_shentsize
	order.PutUint16(header[60:], uint16(count))      // e_shnum
	order.PutUint16(header[62:], uint16(count-1))    // e_shstrndx

	sectionHeaders := new(bytes.Buffer)
	sectionHeaders.Write(make([]byte, sectionHeaderSize))

	for _, name := range names {
		sectionHeaders.Write(sectionHeader(nameOffsets[name], elf.SHT_PROGBITS, offsets[name], uint64(len(sections[name]))))
	}
	sectionHeaders.Write(sectionHeader(nameOffsets[".shstrtab"], elf.SHT_STRTAB, nameTableOffset, uint64(nameTable.Len())))

	file := new(bytes.Buffer)
	file.Write(header)
	file.Write(sectionHeaders.Bytes())
	file.Write(body.Bytes())

	return file.Bytes()
}

func sectionHeader(name uint32, kind elf.SectionType, offset, size uint64) []byte {
	header := make([]byte, 64)
	order := binary.LittleEndian

	order.PutUint32(header[0:], name)
	order.PutUint32(header[4:], uint32(kind))
	order.PutUint64(header[24:], offset)
	order.PutUint64(header[32:], size)
	order.PutUint64(header[56:], 1) // sh_addralign

	return header
}
