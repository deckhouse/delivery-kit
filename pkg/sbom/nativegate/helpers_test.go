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
	"os"
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
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func fixtureDigest(body []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(body)) }

func fixtureContractBOM() *cdx.BOM {
	ginkgo.GinkgoHelper()
	data, err := os.ReadFile("testdata/contract-example-v1.json")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	var bom cdx.BOM
	gomega.Expect(json.Unmarshal(data, &bom)).To(gomega.Succeed())
	return &bom
}

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
	return fixtureRegistryPackageImage(ctx, fixtureImageWithLinks(map[string][]byte{"/usr/share/data": []byte("original")}, map[string]string{"/usr/share/current": "data"}))
}

func fixtureRegistryPackageImage(ctx context.Context, img v1.Image) (sources.Source, TrustedPackages) {
	ginkgo.GinkgoHelper()
	gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New(registry.Logger(log.New(ginkgo.GinkgoWriter, "", 0))))
	ginkgo.DeferCleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://") + "/packages"
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
	return fixtureImageWithLinkTypes(files, links, nil)
}

func fixtureImageWithLinkTypes(files map[string][]byte, links, hardlinks map[string]string) v1.Image {
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
	for name, target := range hardlinks {
		gomega.Expect(w.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Typeflag: tar.TypeLink, Linkname: strings.TrimPrefix(target, "/"), Mode: 0o644})).To(gomega.Succeed())
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

// dynELF describes the ELF file a runtime test needs: its dynamic section, loader, and
// read-only data. Only what the runtime and loader models read is written.
type dynELF struct {
	Type    elf.Type
	Machine elf.Machine
	Interp  string
	Needed  []string
	Sonames []string
	Rpath   string
	Runpath string
	// Dynamic forces a dynamic section even when nothing is needed.
	Dynamic bool
	// Rodata is written NUL-terminated into a .rodata section.
	Rodata []string
}

func (s dynELF) bytes() []byte {
	ginkgo.GinkgoHelper()
	o := binary.LittleEndian
	machine := s.Machine
	if machine == 0 {
		machine = elf.EM_X86_64
	}
	dynamic := s.Dynamic || len(s.Needed) > 0 || len(s.Sonames) > 0 || s.Rpath != "" || s.Runpath != ""

	dynstr := []byte{0}
	str := func(text string) uint64 {
		offset := uint64(len(dynstr))
		dynstr = append(dynstr, text...)
		dynstr = append(dynstr, 0)
		return offset
	}
	var entries []elf.Dyn64
	for _, name := range s.Needed {
		entries = append(entries, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: str(name)})
	}
	for _, name := range s.Sonames {
		entries = append(entries, elf.Dyn64{Tag: int64(elf.DT_SONAME), Val: str(name)})
	}
	if s.Rpath != "" {
		entries = append(entries, elf.Dyn64{Tag: int64(elf.DT_RPATH), Val: str(s.Rpath)})
	}
	if s.Runpath != "" {
		entries = append(entries, elf.Dyn64{Tag: int64(elf.DT_RUNPATH), Val: str(s.Runpath)})
	}
	entries = append(entries, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	var dynamicBytes bytes.Buffer
	gomega.Expect(binary.Write(&dynamicBytes, o, entries)).To(gomega.Succeed())
	var rodata []byte
	for _, text := range s.Rodata {
		rodata = append(rodata, text...)
		rodata = append(rodata, 0)
	}

	var body bytes.Buffer
	body.Write(make([]byte, 64))
	phnum := 0
	if s.Interp != "" {
		phnum = 1
		body.Write(make([]byte, 56))
	}
	interpOffset := body.Len()
	if s.Interp != "" {
		body.WriteString(s.Interp + "\x00")
	}
	place := func(data []byte) int {
		for body.Len()%8 != 0 {
			body.WriteByte(0)
		}
		offset := body.Len()
		body.Write(data)
		return offset
	}
	names := []byte("\x00.shstrtab\x00.dynstr\x00.dynamic\x00.rodata\x00")
	type section struct {
		name, kind       uint32
		flags            uint64
		offset, size     int
		link, info       uint32
		addralign, entsz uint64
	}
	sections := []section{{}}
	shstrtabOffset := place(names)
	sections = append(sections, section{name: 1, kind: uint32(elf.SHT_STRTAB), offset: shstrtabOffset, size: len(names), addralign: 1})
	if dynamic {
		strOffset := place(dynstr)
		sections = append(sections, section{name: 11, kind: uint32(elf.SHT_STRTAB), flags: uint64(elf.SHF_ALLOC), offset: strOffset, size: len(dynstr), addralign: 1})
		dynOffset := place(dynamicBytes.Bytes())
		sections = append(sections, section{name: 19, kind: uint32(elf.SHT_DYNAMIC), flags: uint64(elf.SHF_ALLOC), offset: dynOffset, size: dynamicBytes.Len(), link: 2, addralign: 8, entsz: 16})
	}
	if rodata != nil {
		offset := place(rodata)
		sections = append(sections, section{name: 28, kind: uint32(elf.SHT_PROGBITS), flags: uint64(elf.SHF_ALLOC), offset: offset, size: len(rodata), addralign: 1})
	}
	shoff := place(nil)
	for _, sec := range sections {
		header := elf.Section64{Name: sec.name, Type: sec.kind, Flags: sec.flags, Off: uint64(sec.offset), Size: uint64(sec.size), Link: sec.link, Info: sec.info, Addralign: sec.addralign, Entsize: sec.entsz}
		gomega.Expect(binary.Write(&body, o, header)).To(gomega.Succeed())
	}
	out := body.Bytes()
	header := elf.Header64{Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}, Type: uint16(s.Type), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: 1, Shoff: uint64(shoff)}
	if s.Interp != "" {
		header.Phoff, header.Phentsize, header.Phnum = 64, 56, uint16(phnum)
		var ph bytes.Buffer
		gomega.Expect(binary.Write(&ph, o, elf.Prog64{Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R), Off: uint64(interpOffset), Filesz: uint64(len(s.Interp) + 1), Memsz: uint64(len(s.Interp) + 1), Align: 1})).To(gomega.Succeed())
		copy(out[64:], ph.Bytes())
	}
	var hb bytes.Buffer
	gomega.Expect(binary.Write(&hb, o, header)).To(gomega.Succeed())
	copy(out, hb.Bytes())
	return out
}

// rtImage is the file system of a runtime test: files, symbolic links, and the files an
// image's SBOM records account for (every ELF file by default).
type rtImage struct {
	files   map[string][]byte
	links   map[string]string
	unknown map[string]bool // ELF files the SBOM does not account for
	// recorded overrides the SHA-256 the SBOM states for a file (a file changed after its record).
	recorded map[string]string
}

const (
	loaderPath = "/lib/ld-linux-x86-64.so.2"
	interpName = "/lib64/ld-linux-x86-64.so.2"
)

func glibcLoader() []byte {
	return dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/lib/", "/usr/lib/", "/etc/ld.so.cache"}}.bytes()
}

// baseImage is a dynamic executable, the loader it names through a link, and its library behind a link.
func baseImage() *rtImage {
	return &rtImage{
		files: map[string][]byte{
			loaderPath:               glibcLoader(),
			"/usr/bin/app":           dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}}.bytes(),
			"/usr/lib/libfoo.so.1.0": dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes(),
		},
		links:   map[string]string{interpName: loaderPath, "/usr/lib/libfoo.so.1": "libfoo.so.1.0"},
		unknown: map[string]bool{},
	}
}

func (i *rtImage) deps(partial bool) (map[string][]string, []string, error) {
	ginkgo.GinkgoHelper()
	index := &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: i.links}
	fs := &filesystem{index: index, bodies: map[string][]byte{}, executable: map[string]bool{}}
	present := map[string]Record{}
	for name, body := range i.files {
		index.Files[name] = shippedscope.File{Digest: digest(body), Size: int64(len(body))}
		fs.bodies[name] = body
		if bytes.HasPrefix(body, []byte("\x7fELF")) && !i.unknown[name] {
			present[name] = Record{Path: name, SHA256: digest(body)}
			if sum, ok := i.recorded[name]; ok {
				present[name] = Record{Path: name, SHA256: sum}
			}
		}
	}
	return runtimeDependencies(fs, present, partial)
}
