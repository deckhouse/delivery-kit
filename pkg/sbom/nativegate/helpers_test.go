package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/docker_registry"
	osPm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

func fixtureDigest(body []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(body)) }

func fixtureComponent(kind string) cdx.Component {
	return cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: kind, Name: kind, Version: "1", PackageURL: "pkg:generic/" + kind + "@1", Properties: &[]cdx.Property{{Name: "dk:source", Value: `{"kind":"` + kind + `","locator":"registry.example.invalid/packages","checksum":"sha256:` + strings.Repeat("1", 64) + `"}`}}}
}

func fixturePackageSet(destination string) *PackageSet {
	ginkgo.GinkgoHelper()
	img := fixtureImage(map[string][]byte{"/usr/include/sdk.h": []byte("original")})
	pin, err := img.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	view, err := original.NewOriginalPackage(img)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	packet := osPm.PmPackageInfo{Name: "sdk", Version: "1", Digest: pin.String(), Arch: []string{"linux/amd64"}}
	data, err := json.Marshal(packet)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	component := fixtureComponent("pm")
	component.Name = "sdk"
	component.Properties = &[]cdx.Property{{Name: "dk:source", Value: `{"kind":"pm","locator":"registry.example.invalid/packages","checksum":"` + pin.String() + `"}`}}
	return &PackageSet{resolved: []*resolvedSource{{ID: "sdk", Source: sources.Source{Registry: "registry.example.invalid/packages", Platform: "linux/amd64", Packet: data}, Package: packet, Original: view, Root: originalRoot{Pin: pin, Image: img}}}, Originals: []Original{{Path: destination, SourcePath: "usr/include/sdk.h", SHA256: fixtureDigest([]byte("original")), Component: component, Kind: "pm"}}}
}

func fixtureRecord(profile, platform string) map[string]any {
	artifact := "elf"
	if profile == "c-object" || profile == "c-relocatable" {
		artifact = "object"
	}
	return map[string]any{
		"schema": "pm.buildinfo/v1", "artifact": artifact, "profile": map[string]any{"id": profile, "revision": 1, "platform": platform}, "subject": "app", "complete": true,
		"components": []any{map[string]any{"id": "app", "name": "app", "version": "1", "source": map[string]string{"kind": "declared", "locator": "dk:image:app"}}},
		"inputs":     []any{}, "tools": []any{map[string]string{"name": "gcc", "version": "16", "sha256": "sha256:" + strings.Repeat("1", 64)}},
	}
}

func fixtureArchive(member string, content []byte) []byte {
	ginkgo.GinkgoHelper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", member+"/", 0, 0, 0, "644", len(content))
	gomega.Expect(len(header)).To(gomega.Equal(60))
	body := append([]byte("!<arch>\n"+header), content...)
	if len(content)%2 != 0 {
		body = append(body, '\n')
	}
	return body
}

func fixtureRegistryPackage(ctx context.Context) (sources.Source, TrustedPackages) {
	ginkgo.GinkgoHelper()
	gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New(registry.Logger(log.New(ginkgo.GinkgoWriter, "", 0))))
	ginkgo.DeferCleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://") + "/packages"
	img := fixtureImageWithLinks(map[string][]byte{"/usr/share/data": []byte("original")}, map[string]string{"/usr/share/current": "data"})
	ref, err := name.NewTag(repo + ":data")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.Write(ref, img, remote.WithContext(ctx))).To(gomega.Succeed())
	pin, err := img.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	packet := osPm.PmPackageInfo{Name: "data", Version: "1", Digest: pin.String(), Arch: []string{"linux/amd64"}}
	data, err := json.Marshal(packet)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return sources.Source{Registry: repo, Platform: "linux/amd64", Packet: data}, TrustedPackages{repo + "@" + pin.String(): packet}
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
	if record == nil {
		header.Shnum = 2
	}
	var body bytes.Buffer
	for _, value := range []any{header, note.Bytes(), names, elf.Section64{}, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(64 + note.Len()), Size: uint64(len(names)), Addralign: 1}, elf.Section64{Name: 11, Type: uint32(elf.SHT_NOTE), Off: 64, Size: uint64(note.Len()), Addralign: 4}} {
		gomega.Expect(binary.Write(&body, binary.LittleEndian, value)).To(gomega.Succeed())
	}
	return body.Bytes()
}

func fixtureImage(files map[string][]byte) v1.Image {
	return fixtureImageWithLinks(files, map[string]string{})
}

func fixtureImageWithLinks(files map[string][]byte, links map[string]string) v1.Image {
	ginkgo.GinkgoHelper()
	var body bytes.Buffer
	w := tar.NewWriter(&body)
	for name, content := range files {
		gomega.Expect(w.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: 0o644, Size: int64(len(content))})).To(gomega.Succeed())
		_, err := w.Write(content)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	for name, target := range links {
		gomega.Expect(w.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777})).To(gomega.Succeed())
	}
	gomega.Expect(w.Close()).To(gomega.Succeed())
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body.Bytes())), nil })
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	img, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	cfg, err := img.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	cfg.OS, cfg.Architecture = "linux", "amd64"
	img, err = mutate.ConfigFile(img, cfg)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return img
}
