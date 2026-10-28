package nativegate

import (
	"bytes"
	"debug/elf"
	"encoding/binary"

	"github.com/onsi/gomega"
)

func minimalRuntimeELF(kind elf.Type) []byte {
	var body bytes.Buffer
	header := elf.Header64{
		Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:  uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Ehsize: 64,
	}
	gomega.Expect(binary.Write(&body, binary.LittleEndian, header)).To(gomega.Succeed())
	return body.Bytes()
}

func runtimeError(fs *filesystem, present map[string]Record) error {
	_, err := runtimeDependencies(fs, present)
	return err
}

func runtimeTargets(fs *filesystem, present map[string]Record, name string) []string {
	edges, err := runtimeDependencies(fs, present)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return edges[name]
}
