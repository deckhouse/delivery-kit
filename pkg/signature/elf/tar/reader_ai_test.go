package tar_test

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"testing"

	elfTar "github.com/werf/werf/v2/pkg/signature/elf/tar"
)

// elfHeader builds a minimal valid ELF header prefix for the given machine.
func elfHeader(machine elf.Machine) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	b[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	b[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	binary.LittleEndian.PutUint16(b[18:20], uint16(machine))
	return b
}

func makeTar(t *testing.T, files map[string][]byte, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range order {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestAI_ReaderDetectsELFAndPreservesBody verifies prefix-based ELF detection
// matches the supported-machine gating and that the full entry body is still
// readable after Next() (no bytes lost by the peek).
func TestAI_ReaderDetectsELFAndPreservesBody(t *testing.T) {
	x86 := append(elfHeader(elf.EM_X86_64), []byte("PAYLOAD-x86-tail")...)
	arm := append(elfHeader(elf.EM_AARCH64), []byte("arm-tail")...)
	short := []byte{0x7f, 'E', 'L', 'F'} // valid magic but truncated before e_machine
	txt := []byte("hello world, not an elf file at all")

	order := []string{"bin/x86.elf", "bin/arm.elf", "short", "hello.txt"}
	files := map[string][]byte{
		"bin/x86.elf": x86,
		"bin/arm.elf": arm,
		"short":       short,
		"hello.txt":   txt,
	}
	wantELF := map[string]bool{
		"bin/x86.elf": true,  // EM_X86_64 → ELF
		"bin/arm.elf": false, // unsupported machine → not classified ELF
		"short":       false, // truncated before e_machine
		"hello.txt":   false, // no magic
	}

	r := elfTar.NewReader(tar.NewReader(bytes.NewReader(makeTar(t, files, order))))

	seen := 0
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if h.IsELF != wantELF[h.Name] {
			t.Fatalf("%s: IsELF=%v want %v", h.Name, h.IsELF, wantELF[h.Name])
		}
		body, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: ReadAll body: %v", h.Name, err)
		}
		if !bytes.Equal(body, files[h.Name]) {
			t.Fatalf("%s: body lost bytes: got %d want %d", h.Name, len(body), len(files[h.Name]))
		}
		seen++
	}
	if seen != len(order) {
		t.Fatalf("saw %d entries, want %d", seen, len(order))
	}
}
