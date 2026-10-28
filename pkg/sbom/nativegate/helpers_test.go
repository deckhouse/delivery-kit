package nativegate

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"github.com/onsi/gomega"
)

func fixtureBuildRecord(kind elf.Type) *shared.BuildRecord {
	profile := "c-static"
	if kind == elf.ET_DYN {
		profile = "c-dynamic"
	}
	return &shared.BuildRecord{
		Schema: "pm.buildinfo/v1", Artifact: "elf", Profile: shared.BuildProfile{ID: profile, Revision: "1", Platform: "linux/amd64"}, Subject: "app", Complete: true,
		Components: []shared.BuildComponent{{ID: "app", Name: kind.String(), Version: "1", Source: shared.BuildSource{Kind: "declared", Locator: "https://example.invalid/" + kind.String()}}},
		Inputs:     []shared.BuildInput{}, Tools: []shared.BuildTool{{Name: "fixture-tool", Version: "1.0", SHA256: "sha256:" + strings.Repeat("2", 64)}},
	}
}

func minimalRuntimeELF(kind elf.Type) []byte {
	return runtimeELFWithRecord(kind, fixtureBuildRecord(kind))
}

func runtimeELFWithRecord(kind elf.Type, record *shared.BuildRecord) []byte {
	payload, err := json.Marshal(map[string]any{"type": "pm", "sbom": record})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var note bytes.Buffer
	for _, n := range []uint32{4, uint32(len(payload)), 0xcafe1a7e} {
		gomega.Expect(binary.Write(&note, binary.LittleEndian, n)).To(gomega.Succeed())
	}
	_, err = note.Write(append([]byte("FDO\x00"), payload...))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	for note.Len()%4 != 0 {
		gomega.Expect(note.WriteByte(0)).To(gomega.Succeed())
	}
	names := []byte("\x00.shstrtab\x00.note.package\x00")
	header := elf.Header64{Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}, Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Shentsize: 64, Shnum: 3, Shstrndx: 1, Shoff: uint64(64 + note.Len() + len(names))}
	var body bytes.Buffer
	for _, value := range []any{header, note.Bytes(), names, elf.Section64{}, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(64 + note.Len()), Size: uint64(len(names)), Addralign: 1}, elf.Section64{Name: 11, Type: uint32(elf.SHT_NOTE), Off: 64, Size: uint64(note.Len()), Addralign: 4}} {
		gomega.Expect(binary.Write(&body, binary.LittleEndian, value)).To(gomega.Succeed())
	}
	return body.Bytes()
}

func fixturePolicy(name string) *Policy {
	return &Policy{Profiles: []string{"c-static", "c-dynamic"}, Tools: []Tool{{Name: "fixture-tool", Version: "1.0", SHA256: "sha256:" + strings.Repeat("2", 64)}}, Images: map[string]ImagePolicy{name: {Role: "final"}}}
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

func fixtureFileMode(name string) int64 {
	if strings.HasPrefix(name, "/var/lib/pm/") {
		return 0o644
	}
	return 0o755
}
