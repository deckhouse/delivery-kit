package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

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
	place := func(data []byte) (offset int) {
		for body.Len()%8 != 0 {
			body.WriteByte(0)
		}
		offset = body.Len()
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

var _ = ginkgo.Describe("runtime dependencies", func() {
	ginkgo.It("resolves a name through the loader's directories and the links of the image", func() {
		edges, unresolved, err := baseImage().deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(unresolved).To(gomega.BeEmpty())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ConsistOf(loaderPath, "/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.It("searches the loader's directories in the order the loader holds them", func() {
		image := baseImage()
		image.files["/lib/libfoo.so.1.0"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes()
		image.links["/lib/libfoo.so.1"] = "libfoo.so.1.0"
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ContainElement("/lib/libfoo.so.1.0"))
		gomega.Expect(edges["/usr/bin/app"]).NotTo(gomega.ContainElement("/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.It("prefers a library in DT_RUNPATH to one in the loader's directories", func() {
		image := baseImage()
		image.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "/opt/private"}.bytes()
		image.files["/opt/private/libfoo.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes()
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ContainElement("/opt/private/libfoo.so.1"))
		gomega.Expect(edges["/usr/bin/app"]).NotTo(gomega.ContainElement("/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.DescribeTable("follows DT_RUNPATH before the loader's directories", func(runpath string) {
		image := baseImage()
		delete(image.files, "/usr/lib/libfoo.so.1.0")
		delete(image.links, "/usr/lib/libfoo.so.1")
		image.files["/opt/app/bin/tool"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: runpath}.bytes()
		delete(image.files, "/usr/bin/app")
		image.files["/opt/app/private/libfoo.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes()
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/opt/app/bin/tool"]).To(gomega.ContainElement("/opt/app/private/libfoo.so.1"))
	},
		ginkgo.Entry("$ORIGIN", "$ORIGIN/../private"),
		ginkgo.Entry("${ORIGIN}", "${ORIGIN}/../private"),
		ginkgo.Entry("absolute directory", "/opt/app/private"),
	)

	ginkgo.It("resolves a DT_NEEDED written as an absolute path, and through a directory link", func() {
		image := baseImage()
		image.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"/usr/lib64/libfoo.so.1.0"}}.bytes()
		image.links["/usr/lib64"] = "lib"
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ContainElement("/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.It("asks nothing of an image of static files", func() {
		image := &rtImage{files: map[string][]byte{"/usr/bin/static": dynELF{Type: elf.ET_EXEC}.bytes()}, links: map[string]string{}, unknown: map[string]bool{}}
		edges, unresolved, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges).To(gomega.BeEmpty())
		gomega.Expect(unresolved).To(gomega.BeEmpty())
	})

	ginkgo.It("passes over a cross-built file that loads nothing", func() {
		image := baseImage()
		image.files["/usr/bin/arm"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_AARCH64}.bytes()
		_, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.DescribeTable("refuses what it cannot resolve to one accounted file", func(change func(*rtImage), want string) {
		image := baseImage()
		change(image)
		_, _, err := image.deps(false)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(want)))
	},
		ginkgo.Entry("a missing library", func(i *rtImage) {
			delete(i.files, "/usr/lib/libfoo.so.1.0")
			delete(i.links, "/usr/lib/libfoo.so.1")
		}, "missing runtime dependency libfoo.so.1"),
		ginkgo.Entry("a library the SBOM does not account for", func(i *rtImage) { i.unknown["/usr/lib/libfoo.so.1.0"] = true }, "unknown runtime dependency /usr/lib/libfoo.so.1.0"),
		ginkgo.Entry("a library answering to another SONAME", func(i *rtImage) {
			i.files["/usr/lib/libfoo.so.1.0"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libbar.so.1"}}.bytes()
		}, "runtime SONAME mismatch"),
		ginkgo.Entry("a library that is not an ELF file", func(i *rtImage) {
			i.files["/usr/lib/libfoo.so.1.0"] = []byte("not elf")
			i.unknown["/usr/lib/libfoo.so.1.0"] = false
		}, "unknown runtime dependency"),
		ginkgo.Entry("a relative DT_NEEDED", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"lib/libfoo.so.1"}}.bytes()
		}, "relative DT_NEEDED unsupported lib/libfoo.so.1"),
		ginkgo.Entry("DT_RPATH", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Rpath: "/usr/lib"}.bytes()
		}, "DT_RPATH inheritance unsupported"),
		ginkgo.Entry("a RUNPATH variable other than ORIGIN", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "/usr/$LIB"}.bytes()
		}, "unsupported runtime search path /usr/$LIB"),
		ginkgo.Entry("a relative RUNPATH directory", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "lib"}.bytes()
		}, "unsupported runtime search path lib"),
		ginkgo.Entry("a symbolic link cycle", func(i *rtImage) {
			i.links["/usr/lib/libfoo.so.1"] = "libfoo.so.1"
		}, "symlink cycle"),
		ginkgo.Entry("two libraries claiming one SONAME in a closure", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libx.so.1", "liby.so.1"}}.bytes()
			i.files["/usr/lib/libx.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libx.so.1", "shared.so.1"}}.bytes()
			i.files["/usr/lib/liby.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"liby.so.1", "shared.so.1"}}.bytes()
		}, "conflicting runtime SONAME shared.so.1"),
		ginkgo.Entry("an ELF file of an unsupported machine", func(i *rtImage) {
			i.files["/usr/bin/ppc"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_PPC64}.bytes()
		}, "unsupported runtime ELF architecture /usr/bin/ppc"),
		ginkgo.Entry("a cross-built file that needs a library", func(i *rtImage) {
			i.files["/usr/bin/arm"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_AARCH64, Needed: []string{"libc.so.6"}}.bytes()
		}, "linux/arm64 executable needs libc.so.6"),
		ginkgo.Entry("a cross-built file that names a loader", func(i *rtImage) {
			i.files["/usr/bin/arm"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_AARCH64, Interp: "/lib/ld-linux-aarch64.so.1"}.bytes()
		}, "linux/arm64 executable needs a runtime loader"),
	)

	ginkgo.DescribeTable("refuses an image whose loader it cannot state", func(change func(*rtImage), want string) {
		image := baseImage()
		change(image)
		_, _, err := image.deps(false)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(want)))
	},
		ginkgo.Entry("a loader the SBOM does not account for", func(i *rtImage) { i.unknown[loaderPath] = true }, "unknown runtime loader"),
		ginkgo.Entry("a loader changed after its record", func(i *rtImage) {
			i.recorded = map[string]string{loaderPath: fixtureDigest([]byte("the file the record describes"))}
		}, "hash-mismatch: the runtime loader /lib/ld-linux-x86-64.so.2"),
		ginkgo.Entry("a loader missing from the image", func(i *rtImage) { delete(i.files, loaderPath) }, "missing runtime loader"),
		ginkgo.Entry("a loader answering to another SONAME", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libc.so.6"}, Rodata: []string{"/lib/", "/etc/ld.so.cache"}}.bytes()
		}, "runtime loader SONAME mismatch"),
		ginkgo.Entry("a loader stating no directories", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/etc/ld.so.cache"}}.bytes()
		}, "states no search directories"),
		ginkgo.Entry("a loader stating no cache", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/lib/"}}.bytes()
		}, "states no cache file"),
		ginkgo.Entry("a loader stating two caches", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/lib/", "/etc/ld.so.cache", "/var/ld.so.cache"}}.bytes()
		}, "states 2 cache files"),
		ginkgo.Entry("a loader that is not an ELF file", func(i *rtImage) { i.files[loaderPath] = []byte("#!/bin/sh") }, "unknown runtime loader"),
		ginkgo.Entry("two loaders in one image", func(i *rtImage) {
			i.files["/lib/ld-musl.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-musl.so.1"}, Rodata: []string{"/lib/", "/etc/ld.so.cache"}}.bytes()
			i.files["/usr/bin/other"] = dynELF{Type: elf.ET_EXEC, Interp: "/lib/ld-musl.so.1"}.bytes()
		}, "names 2 runtime loaders"),
		ginkgo.Entry("a dynamic library and no executable that names a loader", func(i *rtImage) {
			delete(i.files, "/usr/bin/app")
		}, "no executable of this image names a runtime loader"),
		ginkgo.Entry("the loader's cache in the image", func(i *rtImage) { i.files["/etc/ld.so.cache"] = []byte("cache") }, "unsupported dynamic loader feature /etc/ld.so.cache"),
		ginkgo.Entry("the loader's cache behind a link", func(i *rtImage) {
			i.files["/var/cache/ld.so.cache"] = []byte("cache")
			i.links["/etc"] = "/var/cache"
		}, "unsupported dynamic loader feature /etc/ld.so.cache"),
		ginkgo.Entry("a preload list", func(i *rtImage) { i.files["/etc/ld.so.preload"] = []byte("/usr/lib/libhook.so") }, "unsupported dynamic loader feature /etc/ld.so.preload"),
		ginkgo.Entry("glibc-hwcaps directories", func(i *rtImage) { i.files["/usr/lib/glibc-hwcaps/x86-64-v3/libfoo.so.1"] = []byte("x") }, "unsupported dynamic loader feature"),
	)

	ginkgo.Describe("a partial runtime", func() {
		ginkgo.It("excuses only the names no file of the image answers", func() {
			image := &rtImage{files: map[string][]byte{"/usr/bin/app": dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libc.so.6"}}.bytes()}, links: map[string]string{}, unknown: map[string]bool{}}
			_, unresolved, err := image.deps(true)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(unresolved).To(gomega.ConsistOf("libc.so.6", interpName))
		})

		ginkgo.It("is refused where the image holds the loader its executables name", func() {
			_, _, err := baseImage().deps(true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("declares a partial runtime but holds the runtime loader")))
		})

		ginkgo.It("is refused where every name resolves inside the image", func() {
			image := &rtImage{files: map[string][]byte{"/usr/bin/static": dynELF{Type: elf.ET_EXEC, Dynamic: true}.bytes()}, links: map[string]string{}, unknown: map[string]bool{}}
			_, _, err := image.deps(true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("every runtime name its files state resolves inside it")))
		})

		ginkgo.It("still refuses a library the SBOM does not account for", func() {
			image := &rtImage{files: map[string][]byte{
				"/usr/bin/app":         dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "/usr/lib"}.bytes(),
				"/usr/lib/libfoo.so.1": dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes(),
			}, links: map[string]string{}, unknown: map[string]bool{"/usr/lib/libfoo.so.1": true}}
			_, _, err := image.deps(true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unknown runtime dependency /usr/lib/libfoo.so.1")))
		})
	})
})

var _ = ginkgo.Describe("the dynamic loader environment of an image", func() {
	verify := func(env ...string) error {
		ginkgo.GinkgoHelper()
		img := fixtureImage(nil)
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg.Config.Env = env
		img, err = mutate.ConfigFile(img, cfg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		return Verify(context.Background(), img, cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
	}

	ginkgo.DescribeTable("refuses a variable that changes what the loader loads", func(variable string) {
		err := verify("PATH=/usr/bin", variable+"=/opt/lib")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader environment " + variable)))
	}, ginkgo.Entry("LD_LIBRARY_PATH", "LD_LIBRARY_PATH"), ginkgo.Entry("LD_PRELOAD", "LD_PRELOAD"), ginkgo.Entry("LD_AUDIT", "LD_AUDIT"))

	ginkgo.It("accepts an empty value, other variables and a name that only starts like one", func() {
		gomega.Expect(verify("PATH=/usr/bin", "LD_LIBRARY_PATH=", "LD_LIBRARY_PATH_NOTE=x", "LD_DEBUG=libs", strings.Repeat("A", 3)+"=b")).To(gomega.Succeed())
	})
})
