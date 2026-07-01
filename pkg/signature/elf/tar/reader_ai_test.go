package tar_test

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	elfTar "github.com/werf/werf/v2/pkg/signature/elf/tar"
)

// elfHeaderAI builds a minimal valid ELF header prefix for the given machine.
func elfHeaderAI(machine elf.Machine) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	b[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	b[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	b[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(b[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:24], uint32(elf.EV_CURRENT))
	return b
}

func makeTarAI(files map[string][]byte, order []string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range order {
		body := files[name]
		Expect(tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})).To(Succeed())
		_, err := tw.Write(body)
		Expect(err).To(Succeed())
	}
	Expect(tw.Close()).To(Succeed())
	return buf.Bytes()
}

var _ = Describe("Reader ELF prefix detection (AI)", func() {
	It("detects supported ELF machines and preserves the full body", func() {
		x86 := append(elfHeaderAI(elf.EM_X86_64), []byte("PAYLOAD-x86-tail")...)
		arm := append(elfHeaderAI(elf.EM_AARCH64), []byte("arm-tail")...)
		magicOnly := []byte{0x7f, 'E', 'L', 'F'} // magic but truncated before version/machine
		txt := []byte("hello world, not an elf file at all")

		order := []string{"bin/x86.elf", "bin/arm.elf", "magic-only", "hello.txt"}
		files := map[string][]byte{
			"bin/x86.elf": x86,
			"bin/arm.elf": arm,
			"magic-only":  magicOnly,
			"hello.txt":   txt,
		}
		wantELF := map[string]bool{
			"bin/x86.elf": true,  // EM_X86_64 → ELF
			"bin/arm.elf": false, // unsupported machine → not ELF
			"magic-only":  false, // truncated before version/machine
			"hello.txt":   false, // no magic
		}

		r := elfTar.NewReader(tar.NewReader(bytes.NewReader(makeTarAI(files, order))))

		seen := 0
		for {
			h, err := r.Next()
			if err == io.EOF {
				break
			}
			Expect(err).To(Succeed())
			Expect(h.IsELF).To(Equal(wantELF[h.Name]), "IsELF for %s", h.Name)

			body, err := io.ReadAll(r)
			Expect(err).To(Succeed())
			Expect(body).To(Equal(files[h.Name]), "body for %s", h.Name)
			seen++
		}
		Expect(seen).To(Equal(len(order)))
	})

	It("rejects files with ELF magic but an invalid version field", func() {
		bad := elfHeaderAI(elf.EM_X86_64)
		bad[elf.EI_VERSION] = 0 // invalid EI_VERSION
		bad = append(bad, []byte("tail")...)

		order := []string{"bad.elf"}
		files := map[string][]byte{"bad.elf": bad}

		r := elfTar.NewReader(tar.NewReader(bytes.NewReader(makeTarAI(files, order))))
		h, err := r.Next()
		Expect(err).To(Succeed())
		Expect(h.IsELF).To(BeFalse())
		body, err := io.ReadAll(r)
		Expect(err).To(Succeed())
		Expect(body).To(Equal(bad))
	})

	It("rejects a truncated file smaller than the ELF header", func() {
		// Valid ident + x86_64 machine + version, but only 24 bytes total — too
		// small to be a real ELF; debug/elf.NewFile would have rejected it too.
		trunc := elfHeaderAI(elf.EM_X86_64)[:elfMinPeek]

		order := []string{"trunc.elf"}
		files := map[string][]byte{"trunc.elf": trunc}

		r := elfTar.NewReader(tar.NewReader(bytes.NewReader(makeTarAI(files, order))))
		h, err := r.Next()
		Expect(err).To(Succeed())
		Expect(h.IsELF).To(BeFalse())
		body, err := io.ReadAll(r)
		Expect(err).To(Succeed())
		Expect(body).To(Equal(trunc))
	})
})

// elfMinPeek mirrors reader.elfHeaderPeekSize (24) for the truncation case.
const elfMinPeek = 24
