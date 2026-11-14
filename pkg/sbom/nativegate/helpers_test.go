package nativegate

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func fixtureDigest(body []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(body)) }

func fixtureComponent(kind string) cdx.Component {
	return cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: kind, Name: kind, Version: "1", PackageURL: "pkg:generic/" + kind + "@1", Properties: &[]cdx.Property{{Name: "dk:source", Value: `{"kind":"` + kind + `","locator":"registry.example.invalid/packages","checksum":"sha256:` + strings.Repeat("1", 64) + `"}`}}}
}

func fixtureRecord(profile, platform string) map[string]any {
	return map[string]any{"schema": "pm.buildinfo/v1", "artifact": "elf", "profile": map[string]string{"id": profile, "revision": "1", "platform": platform}, "subject": "app", "complete": true,
		"components": []any{map[string]any{"id": "app", "name": "app", "version": "1", "source": map[string]string{"kind": "declared", "locator": "https://example.invalid/app"}}},
		"inputs": []any{}, "tools": []any{map[string]string{"name": "gcc", "version": "16", "sha256": "sha256:" + strings.Repeat("1", 64)}}}
}

func fixtureELF(kind elf.Type, record any) []byte {
	ginkgo.GinkgoHelper()
	var note bytes.Buffer
	if record != nil {
		payload, err := json.Marshal(map[string]any{"type": "pm", "sbom": record})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, n := range []uint32{4, uint32(len(payload)), 0xcafe1a7e} {
			gomega.Expect(binary.Write(&note, binary.LittleEndian, n)).To(gomega.Succeed())
		}
		_, err = note.Write(append([]byte("FDO\x00"), payload...))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for note.Len()%4 != 0 {
			gomega.Expect(note.WriteByte(0)).To(gomega.Succeed())
		}
	}
	names := []byte("\x00.shstrtab\x00.note.package\x00")
	header := elf.Header64{Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}, Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Shentsize: 64, Shnum: 3, Shstrndx: 1, Shoff: uint64(64 + note.Len() + len(names))}
	var body bytes.Buffer
	for _, value := range []any{header, note.Bytes(), names, elf.Section64{}, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(64 + note.Len()), Size: uint64(len(names)), Addralign: 1}, elf.Section64{Name: 11, Type: uint32(elf.SHT_NOTE), Off: 64, Size: uint64(note.Len()), Addralign: 4}} {
		gomega.Expect(binary.Write(&body, binary.LittleEndian, value)).To(gomega.Succeed())
	}
	return body.Bytes()
}

func fixtureImage(files map[string][]byte) v1.Image {
	ginkgo.GinkgoHelper()
	var body bytes.Buffer
	w := tar.NewWriter(&body)
	for name, content := range files {
		gomega.Expect(w.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: 0o644, Size: int64(len(content))})).To(gomega.Succeed())
		_, err := w.Write(content)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(w.Close()).To(gomega.Succeed())
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body.Bytes())), nil })
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	img, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	img, err = mutate.ConfigFile(img, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return img
}
