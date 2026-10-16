package shippedscope

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	buildOnce sync.Once
	builtGo   []byte
	builtTest []byte
	errBuild  error
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

func buildFixtures() {
	GinkgoHelper()

	buildOnce.Do(func() {
		builtGo, builtTest, errBuild = buildGoFixtures()
	})

	Expect(errBuild).NotTo(HaveOccurred())
}

func buildGoFixtures() ([]byte, []byte, error) {
	root, err := os.MkdirTemp("", "shippedscope-fixtures")
	if err != nil {
		return nil, nil, err
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
	}
	for name, body := range sources {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return nil, nil, err
		}
	}

	app := filepath.Join(root, "app")
	binary := filepath.Join(root, "app.bin")
	testBinary := filepath.Join(root, "app.test")

	for _, args := range [][]string{
		{"build", "-o", binary, "."},
		{"test", "-c", "-o", testBinary, "."},
	} {
		command := exec.Command("go", args...)
		command.Dir = app
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOFLAGS=-mod=mod", "CGO_ENABLED=0")

		if output, err := command.CombinedOutput(); err != nil {
			return nil, nil, &exec.ExitError{ProcessState: command.ProcessState, Stderr: output}
		}
	}

	built, err := os.ReadFile(binary)
	if err != nil {
		return nil, nil, err
	}

	builtTest, err := os.ReadFile(testBinary)
	if err != nil {
		return nil, nil, err
	}

	return built, builtTest, nil
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

	var nameTable bytes.Buffer
	nameTable.WriteByte(0)

	nameOffsets := make(map[string]uint32, len(names)+1)
	for _, name := range append(names, ".shstrtab") {
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
