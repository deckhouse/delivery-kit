package nativegate

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func pureGoFixture() ([]byte, []byte, *Policy) {
	ginkgo.GinkgoHelper()
	root := os.Getenv("DK_GO_FIXTURE")
	if root == "" {
		ginkgo.Skip("requires pinned DK_GO_FIXTURE (mandatory in task test:native-poc)")
	}
	body, err := os.ReadFile(filepath.Join(root, "go-pure-elf"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(body)).To(gomega.Equal("sha256:6633c6efe582b616f97743a113cbbbf98a8cf43f22851613e6c36dd6e906280e"))
	expected, err := os.ReadFile(filepath.Join(root, "go-pure-elf.sbom.json"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(expected)).To(gomega.Equal("sha256:294d967f1256a93a69154829806ef3f7aa91190ea4625d55b6e7ba0f561b47e1"))
	policy := &Policy{Schema: "dk.policy/v2", Profiles: []string{"go"}, Images: map[string]ImagePolicy{"app": {Role: "final"}}, Tools: []Tool{
		{Name: "link", Version: "go1.27.3", SHA256: "sha256:c001887c397d482b4aa2f3c702884f36fc37478461cc7d713b6d18116e2ff4ef"},
		{Name: "sbom-helper", Version: "0f8feba7a3e816ef243392a803381e7db37bf3af", SHA256: "sha256:8fbe79b2c7bb50d3abe12f7d02143320d23b1638360084ab3b154f69179fe675"},
		{Name: "compile", Version: "go1.27.3", SHA256: "sha256:7402aee38211af0f5cd2927bb9bd4ea1ebbf54a3b45269c6b7bc73a2451c65d7"},
		{Name: "asm", Version: "go1.27.3", SHA256: "sha256:d9d405813f1927c69177af9454adb84d5c9cc7d61122ba9f3c531694132004b7"},
	}}
	return body, expected, policy
}

func fixtureBuildRecord(kind elf.Type) *shared.BuildRecord {
	profile, artifact := "c-static", "elf"
	switch kind {
	case elf.ET_DYN:
		profile = "c-dynamic"
	case elf.ET_REL:
		profile, artifact = "c-object", "object"
	}
	return &shared.BuildRecord{
		Schema: "pm.buildinfo/v1", Artifact: artifact, Profile: shared.BuildProfile{ID: profile, Revision: "1", Platform: "linux/amd64"}, Subject: "app", Complete: true,
		Components: []shared.BuildComponent{{ID: "app", Name: kind.String(), Version: "1", Source: shared.BuildSource{Kind: "declared", Locator: "https://example.invalid/" + kind.String()}}},
		Inputs:     []shared.BuildInput{}, Tools: []shared.BuildTool{{Name: "fixture-tool", Version: "1.0", SHA256: "sha256:" + strings.Repeat("2", 64)}},
	}
}

func minimalRuntimeELF(kind elf.Type) []byte {
	return runtimeELFWithRecord(kind, fixtureBuildRecord(kind))
}

func runtimeELFWithRecord(kind elf.Type, record any) []byte {
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
	if strings.HasPrefix(name, "/var/lib/pm/") || strings.HasSuffix(name, ".syso") {
		return 0o644
	}
	return 0o755
}

// fixtureLayer makes a layer out of bytes already in hand.
//
// ggcr's LayerFromReader buffers whatever it is given into a temp file it never closes and
// never removes, so a suite that builds a layer per spec leaves thousands of them behind.
// The bytes are here already; handing them back on demand costs nothing and leaves nothing.
func fixtureLayer(body []byte) (v1.Layer, error) {
	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	})
}
