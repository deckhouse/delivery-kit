package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// The pure-Go aarch64 executable of M05's cross capture: no interpreter, nothing
// needed, and a record naming the platform the machine says it is.
const (
	arm64PureName   = "go-pure-elf"
	arm64PureSHA256 = "sha256:ba6e66065484cdacbdc7a3354dcfe2fe391947ebd507ff66bc8f29902241d267"
)

// The dynamic cgo executables of M05's M04 capture, with the runtime objects the
// image holds beside them. git-lfs is the one the acceptance run named.
const (
	cgoDynamicName   = "argo-cont_out_git-lfs"
	cgoDynamicSHA256 = "sha256:641f29640bb98ade1b96ccc728fa0c8a23a36eab03545b8909346a5b6e95fa3f"
	cgoLoaderName    = "argo-cont_rt/ld-linux-x86-64.so.2"
	cgoLoaderSHA256  = "sha256:3cd2fb75ebffc7f74f9923024a10dddf9300e51cbae2dfa427da0948179de4df"
	cgoLibcName      = "argo-cont_rt/libc.so.6"
	cgoResolvName    = "argo-cont_rt/libresolv.so.2"
)

func fixtureBody(root, name, expected string) []byte {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(filepath.Join(root, name))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	if expected != "" {
		gomega.Expect(digest(body)).To(gomega.Equal(expected), name)
	}

	return body
}

func arm64FixtureRoot() string {
	ginkgo.GinkgoHelper()
	root := os.Getenv("DK_ARM64_FIXTURE")
	if root == "" {
		ginkgo.Skip("set DK_ARM64_FIXTURE to the pinned aarch64 capture (go_cgo/arm64-check/artifacts)")
	}

	return root
}

func cgoDynamicFixtureRoot() string {
	ginkgo.GinkgoHelper()
	root := os.Getenv("DK_CGO_DYNAMIC_FIXTURE")
	if root == "" {
		ginkgo.Skip("set DK_CGO_DYNAMIC_FIXTURE to the pinned dynamic cgo capture (M05 M04 evidence)")
	}

	return root
}

// crossELF builds the smallest executable for another machine that debug/elf
// reads, carrying the interpreter and the DT_NEEDED entries asked for. It stands
// in for a cross-built file this image is asked to resolve something for, which
// the pinned captures do not contain.
func crossELF(machine elf.Machine, class elf.Class, interpreter string, needed []string) []byte {
	return elfFile(machine, class, interpreter, "", needed, nil, nil)
}

// namedELF is crossELF with a DT_SONAME of its own.
func namedELF(machine elf.Machine, class elf.Class, interpreter, soname string, needed []string) []byte {
	return elfFile(machine, class, interpreter, soname, needed, nil, nil)
}

// loaderELF is a loader this image could read: it calls itself the name given and keeps
// that search directory and a cache path in its read-only data, the way a glibc rtld
// does.
func loaderELF(soname, dir string) []byte {
	return cachingLoaderELF(soname, dir, "/etc/ld.so.cache")
}

// cachingLoaderELF is a loader that states the cache path given, which is not always the
// one anybody would have assumed.
func cachingLoaderELF(soname, dir, cache string) []byte {
	rodata := append([]byte(dir), 0)
	rodata = append(rodata, cache...)
	rodata = append(rodata, 0)

	return elfFile(elf.EM_X86_64, elf.ELFCLASS64, "", soname, nil, rodata, nil)
}

// elsewhereLoaderELF is a loader holding a directory string in data that is not its
// read-only data: writable data it may rewrite as it runs, and allocated data of another
// kind. Neither says anything about the directories it was built to search.
func elsewhereLoaderELF(soname, dir string, others []extraSection) []byte {
	rodata := append([]byte(dir), 0)
	rodata = append(rodata, "/etc/ld.so.cache\x00"...)

	return elfFile(elf.EM_X86_64, elf.ELFCLASS64, "", soname, nil, rodata, others)
}

// extraSection is a section of a fixture beyond the ones every fixture carries.
type extraSection struct {
	name  string
	flags elf.SectionFlag
	body  []byte
}

func elfFile(machine elf.Machine, class elf.Class, interpreter, soname string, needed []string, rodata []byte, others []extraSection) []byte {
	ginkgo.GinkgoHelper()
	wide := class == elf.ELFCLASS64
	headerSize, progSize, sectionSize, dynSize := 52, 32, 40, 8
	if wide {
		headerSize, progSize, sectionSize, dynSize = 64, 56, 64, 16
	}
	names := []byte("\x00.shstrtab\x00.dynstr\x00.dynamic\x00.rodata\x00")
	const rodataName = 28
	extraNames := make([]uint64, 0, len(others))
	for _, other := range others {
		extraNames = append(extraNames, uint64(len(names)))
		names = append(names, other.name...)
		names = append(names, 0)
	}
	segments := 0
	if interpreter != "" {
		segments = 1
	}
	dynstr := []byte{0}
	offsets := make([]uint64, 0, len(needed))
	for _, name := range needed {
		offsets = append(offsets, uint64(len(dynstr)))
		dynstr = append(dynstr, name...)
		dynstr = append(dynstr, 0)
	}
	sonameOff := uint64(0)
	if soname != "" {
		sonameOff = uint64(len(dynstr))
		dynstr = append(dynstr, soname...)
		dynstr = append(dynstr, 0)
	}
	entries := len(needed)
	if soname != "" {
		entries++
	}
	interpSize := 0
	if segments == 1 {
		interpSize = len(interpreter) + 1
	}
	interpOff := uint64(headerSize + segments*progSize)
	namesOff := interpOff + uint64(interpSize)
	dynstrOff := namesOff + uint64(len(names))
	dynamicOff := dynstrOff + uint64(len(dynstr))
	dynamicSize := uint64((entries + 1) * dynSize)
	rodataOff := dynamicOff + dynamicSize
	extraOffs := make([]uint64, 0, len(others))
	next := rodataOff + uint64(len(rodata))
	for _, other := range others {
		extraOffs = append(extraOffs, next)
		next += uint64(len(other.body))
	}
	sectionsOff := next

	var body bytes.Buffer
	write := func(values ...any) {
		for _, value := range values {
			gomega.Expect(binary.Write(&body, binary.LittleEndian, value)).To(gomega.Succeed())
		}
	}
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	if wide {
		write(elf.Header64{
			Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine),
			Version: uint32(elf.EV_CURRENT), Ehsize: uint16(headerSize),
			Phentsize: uint16(progSize), Phnum: uint16(segments), Phoff: uint64(headerSize),
			Shentsize: uint16(sectionSize), Shnum: uint16(5 + len(others)), Shstrndx: 1, Shoff: sectionsOff,
		})
		if segments == 1 {
			write(elf.Prog64{
				Type: uint32(elf.PT_INTERP), Off: interpOff,
				Filesz: uint64(interpSize), Memsz: uint64(interpSize),
				Align: 1, Flags: uint32(elf.PF_R),
			})
		}
	} else {
		write(elf.Header32{
			Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine),
			Version: uint32(elf.EV_CURRENT), Ehsize: uint16(headerSize),
			Phentsize: uint16(progSize), Phnum: uint16(segments), Phoff: uint32(headerSize),
			Shentsize: uint16(sectionSize), Shnum: uint16(5 + len(others)), Shstrndx: 1, Shoff: uint32(sectionsOff),
		})
		if segments == 1 {
			write(elf.Prog32{
				Type: uint32(elf.PT_INTERP), Off: uint32(interpOff),
				Filesz: uint32(interpSize), Memsz: uint32(interpSize),
				Align: 1, Flags: uint32(elf.PF_R),
			})
		}
	}
	if segments == 1 {
		body.WriteString(interpreter)
		body.WriteByte(0)
	}
	body.Write(names)
	body.Write(dynstr)
	for _, offset := range offsets {
		if wide {
			write(elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: offset})
		} else {
			write(elf.Dyn32{Tag: int32(elf.DT_NEEDED), Val: uint32(offset)})
		}
	}
	if soname != "" {
		if wide {
			write(elf.Dyn64{Tag: int64(elf.DT_SONAME), Val: sonameOff})
		} else {
			write(elf.Dyn32{Tag: int32(elf.DT_SONAME), Val: uint32(sonameOff)})
		}
	}
	if wide {
		write(elf.Dyn64{Tag: int64(elf.DT_NULL)})
	} else {
		write(elf.Dyn32{Tag: int32(elf.DT_NULL)})
	}
	body.Write(rodata)
	for _, other := range others {
		body.Write(other.body)
	}
	sections := []struct {
		name, kind, off, size, link, flags uint64
	}{
		{},
		{1, uint64(elf.SHT_STRTAB), namesOff, uint64(len(names)), 0, 0},
		{11, uint64(elf.SHT_STRTAB), dynstrOff, uint64(len(dynstr)), 0, 0},
		{19, uint64(elf.SHT_DYNAMIC), dynamicOff, dynamicSize, 2, 0},
		{rodataName, uint64(elf.SHT_PROGBITS), rodataOff, uint64(len(rodata)), 0, uint64(elf.SHF_ALLOC)},
	}
	for i, other := range others {
		sections = append(sections, struct {
			name, kind, off, size, link, flags uint64
		}{extraNames[i], uint64(elf.SHT_PROGBITS), extraOffs[i], uint64(len(other.body)), 0, uint64(other.flags)})
	}
	for _, section := range sections {
		if wide {
			write(elf.Section64{
				Name: uint32(section.name), Type: uint32(section.kind), Off: section.off,
				Size: section.size, Link: uint32(section.link), Addralign: 1, Flags: section.flags,
			})
		} else {
			write(elf.Section32{
				Name: uint32(section.name), Type: uint32(section.kind), Off: uint32(section.off),
				Size: uint32(section.size), Link: uint32(section.link), Addralign: 1, Flags: uint32(section.flags),
			})
		}
	}

	return body.Bytes()
}

// nativeFilesystem lays the given bodies out as an image the gate reads, with a
// record standing for each of them as an ordinary payload file would have.
func nativeFilesystem(files map[string][]byte) (*filesystem, map[string]Record) {
	fs := &filesystem{
		index:  &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{}},
		bodies: map[string][]byte{},
	}
	present := map[string]Record{}
	for name, body := range files {
		fs.bodies[name] = body
		fs.index.Files[name] = shippedscope.File{Digest: digest(body)}
		present[name] = Record{Path: name, SHA256: digest(body), Origin: "build"}
	}

	return fs, present
}

func defaultInspector(ctx context.Context) *inspector {
	catalog := emptyCatalog()

	return &inspector{policy: NewDefaultPolicy(ctx, "app"), catalog: &catalog}
}

func compositionOf(record Record) shared.BuildRecord {
	ginkgo.GinkgoHelper()
	var composition shared.BuildRecord
	gomega.Expect(json.Unmarshal(record.Composition, &composition)).To(gomega.Succeed())

	return composition
}

var _ = ginkgo.Describe("Targets the record reader reports and the gate now agrees to check", func() {
	// M05's cross capture ends in `unsupported: embedded elf profile go on
	// linux/arm64 has no DK dependency agreement check`; a pure-Go aarch64
	// executable loads nothing, which is a thing this image can say.
	ginkgo.It("accepts the record of a pure Go executable built for aarch64", func(ctx ginkgo.SpecContext) {
		body := fixtureBody(arm64FixtureRoot(), arm64PureName, arm64PureSHA256)

		record, native, err := defaultInspector(ctx).inspect(body)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(native).To(gomega.BeTrue())
		gomega.Expect(record.Profile).To(gomega.Equal("go"))
		gomega.Expect(compositionOf(record).Artifact).To(gomega.Equal("elf"))
		gomega.Expect(compositionOf(record).Profile.Platform).To(gomega.Equal("linux/arm64"))
	})

	// The whole gate agrees, not the reader alone: a pure Go aarch64 executable
	// shipped as an ordinary payload file is inventoried like any other.
	ginkgo.It("inventories a pure Go aarch64 executable shipped in an image", func(ctx ginkgo.SpecContext) {
		body := fixtureBody(arm64FixtureRoot(), arm64PureName, arm64PureSHA256)

		bom := cdx.NewBOM()
		gomega.Expect(Apply(ctx, NewDefaultPolicy(ctx, "app"), "app",
			fixtureImage(map[string]string{"/usr/local/bin/argocd": string(body)}), nil, bom)).To(gomega.Succeed())

		catalog, err := ReadCatalog([]*cdx.BOM{bom})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.Records).To(gomega.HaveLen(1))
		gomega.Expect(catalog.Records[0].Profile).To(gomega.Equal("go"))
		gomega.Expect(catalog.Records[0].SHA256).To(gomega.Equal(arm64PureSHA256))
	})

	// Nothing of it is resolved against this rootfs, and the reader's word that
	// it loads nothing is checked rather than taken.
	ginkgo.It("asks a pure Go aarch64 executable for its closure and finds it needs none", func() {
		body := fixtureBody(arm64FixtureRoot(), arm64PureName, arm64PureSHA256)
		fs, present := nativeFilesystem(map[string][]byte{"/usr/local/bin/argocd": body})

		edges, err := runtimeDependencies(fs, present)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges).To(gomega.BeEmpty())
	})

	// A dynamic aarch64 executable would have to be resolved through a loader
	// for a machine this image models nothing of, and saying nothing about it is
	// the one honest answer until it does.
	ginkgo.It("refuses an aarch64 executable that needs a loader, naming the machine", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/local/bin/argocd": crossELF(elf.EM_AARCH64, elf.ELFCLASS64, "/lib/ld-linux-aarch64.so.1", nil),
		})

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unsupported: linux/arm64 executable needs a runtime loader, and this image resolves none for that machine")))
	})

	// Needing a shared object is as much a thing this image cannot resolve for
	// that machine as needing a loader, and the refusal names what it would have
	// had to find.
	ginkgo.It("refuses an aarch64 executable that needs a shared object, naming it", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/local/bin/argocd": crossELF(elf.EM_AARCH64, elf.ELFCLASS64, "", []string{"libc.so.6", "libz.so.1"}),
		})

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unsupported: linux/arm64 executable needs libc.so.6, libz.so.1, and this image resolves none for that machine")))
	})

	// The machine in the refusal is the machine of the file, which is how a
	// reader of it learns what this image could not answer for.
	ginkgo.It("names a 32-bit ARM executable by its own machine", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/opt/tool": crossELF(elf.EM_ARM, elf.ELFCLASS32, "", []string{"libc.so.6"}),
		})

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unsupported: linux/arm executable needs libc.so.6")))
	})

	// The acceptance run of the dynamic capture ends in `unsupported: embedded
	// elf profile go-cgo-dynamic on linux/amd64 has no DK dependency agreement
	// check`, for a file whose record the reader reads in full.
	ginkgo.It("accepts the record of a dynamically linked cgo executable", func(ctx ginkgo.SpecContext) {
		body := fixtureBody(cgoDynamicFixtureRoot(), cgoDynamicName, cgoDynamicSHA256)

		record, native, err := defaultInspector(ctx).inspect(body)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(native).To(gomega.BeTrue())
		gomega.Expect(record.Profile).To(gomega.Equal("go-cgo-dynamic"))
		gomega.Expect(compositionOf(record).Profile.Platform).To(gomega.Equal("linux/amd64"))
		// The acceptance run counts 39 components for this file.
		gomega.Expect(record.Components).To(gomega.HaveLen(39))
	})

	// The whole closure of the real capture, through the loader the image holds: the
	// executable names /lib64/ld-linux-x86-64.so.2, this image is usr-merged so that
	// name lands on /usr/lib/ld-linux-x86-64.so.2, and that loader was built to search
	// /usr/lib alone - which is where its libc and libresolv are.
	ginkgo.It("resolves a dynamic cgo executable through the loader the image holds", func() {
		root := cgoDynamicFixtureRoot()
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/git-lfs":              fixtureBody(root, cgoDynamicName, cgoDynamicSHA256),
			"/usr/lib/ld-linux-x86-64.so.2": fixtureBody(root, cgoLoaderName, cgoLoaderSHA256),
			"/usr/lib/libc.so.6":            fixtureBody(root, cgoLibcName, ""),
			"/usr/lib/libresolv.so.2":       fixtureBody(root, cgoResolvName, ""),
		})
		fs.index.Symlinks["/lib64"] = "/usr/lib"

		edges, err := runtimeDependencies(fs, present)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/git-lfs"]).To(gomega.ConsistOf(
			"/usr/lib/libc.so.6", "/usr/lib/libresolv.so.2", "/usr/lib/ld-linux-x86-64.so.2"))
	})

	// The same files laid out the way DK used to assume - loader and objects under
	// /lib64 - are not resolved, because this loader does not look there. The layout
	// the image chooses and the loader it ships have to agree; nothing about the
	// executable can make up for it.
	ginkgo.It("finds nothing for the same files laid out where this loader never looks", func() {
		root := cgoDynamicFixtureRoot()
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/git-lfs":            fixtureBody(root, cgoDynamicName, cgoDynamicSHA256),
			"/lib64/ld-linux-x86-64.so.2": fixtureBody(root, cgoLoaderName, cgoLoaderSHA256),
			"/lib64/libc.so.6":            fixtureBody(root, cgoLibcName, ""),
			"/lib64/libresolv.so.2":       fixtureBody(root, cgoResolvName, ""),
		})

		_, err := runtimeDependencies(fs, present)

		// The executable names the loader under /lib64 and the loader's own libc
		// names it under /usr/lib; with no symlink joining them, the image holds
		// two loaders and states no single closure. This is the layout conflict
		// the acceptance run met, named precisely.
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: this image names 2 runtime loaders")))
	})

	// What the loader states about itself, read out of its own bytes.
	ginkgo.It("reads the search directories and cache file out of the loader", func() {
		body := fixtureBody(cgoDynamicFixtureRoot(), cgoLoaderName, cgoLoaderSHA256)

		model, err := readLoaderModel(body, "/usr/lib/ld-linux-x86-64.so.2")

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(model.dirs).To(gomega.Equal([]string{"/usr/lib"}))
		gomega.Expect(model.cache).To(gomega.Equal("/etc/ld.so.cache"))
	})

	ginkgo.It("refuses a loader that names no cache file", func() {
		body := elfFile(elf.EM_X86_64, elf.ELFCLASS64, "", "ld-linux-x86-64.so.2", nil, []byte("/usr/lib/\x00"), nil)

		_, err := readLoaderModel(body, "/usr/lib/ld-linux-x86-64.so.2")

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("states no cache file this image can read")))
	})

	// The cache answers before the directories do, and the path refused is the one
	// this loader states rather than one DK assumed.
	ginkgo.It("refuses an image holding the cache file its own loader would read", func() {
		root := cgoDynamicFixtureRoot()
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/git-lfs":              fixtureBody(root, cgoDynamicName, cgoDynamicSHA256),
			"/usr/lib/ld-linux-x86-64.so.2": fixtureBody(root, cgoLoaderName, cgoLoaderSHA256),
			"/usr/lib/libc.so.6":            fixtureBody(root, cgoLibcName, ""),
			"/usr/lib/libresolv.so.2":       fixtureBody(root, cgoResolvName, ""),
		})
		fs.index.Symlinks["/lib64"] = "/usr/lib"
		fs.index.Files["/etc/ld.so.cache"] = shippedscope.File{}

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader feature /etc/ld.so.cache")))
	})

	// The loader is a mandatory file like any other: unaccounted for, nothing runs.
	ginkgo.It("refuses an image whose loader this build accounts for in no way", func() {
		root := cgoDynamicFixtureRoot()
		files := map[string][]byte{
			"/usr/bin/git-lfs":              fixtureBody(root, cgoDynamicName, cgoDynamicSHA256),
			"/usr/lib/ld-linux-x86-64.so.2": fixtureBody(root, cgoLoaderName, cgoLoaderSHA256),
			"/usr/lib/libc.so.6":            fixtureBody(root, cgoLibcName, ""),
			"/usr/lib/libresolv.so.2":       fixtureBody(root, cgoResolvName, ""),
		}
		fs, present := nativeFilesystem(files)
		fs.index.Symlinks["/lib64"] = "/usr/lib"
		delete(present, "/usr/lib/ld-linux-x86-64.so.2")

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unknown runtime loader /usr/lib/ld-linux-x86-64.so.2")))
	})

	// A file standing where the interpreter points, that is not the loader this build
	// accounts for, is refused rather than taken for it by position.
	ginkgo.It("refuses an interpreter that lands on some other file", func() {
		root := cgoDynamicFixtureRoot()
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/git-lfs":              fixtureBody(root, cgoDynamicName, cgoDynamicSHA256),
			"/usr/lib/ld-linux-x86-64.so.2": fixtureBody(root, cgoLibcName, ""),
		})
		fs.index.Symlinks["/lib64"] = "/usr/lib"

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"runtime loader SONAME mismatch /usr/lib/ld-linux-x86-64.so.2: it is named as ld-linux-x86-64.so.2 and calls itself libc.so.6")))
	})

	// A file calling itself the loader, that states no directory at all, settles
	// nothing about where this image's names resolve.
	ginkgo.It("refuses a loader whose directories cannot be read from it", func() {
		const interp = "/lib64/ld-linux-x86-64.so.2"
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app": namedELF(elf.EM_X86_64, elf.ELFCLASS64, interp, "", []string{"libfoo.so.1"}),
			interp:         namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "ld-linux-x86-64.so.2", nil),
		})

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: the runtime loader " + interp + " states no search directories this image can read")))
	})

	// The directories searched are the loader's own, and no layout DK might have
	// assumed stands in for them: here the only object is where this loader looks
	// and nowhere DK ever guessed.
	ginkgo.It("finds a dependency only because its own loader searches there", func() {
		const interp = "/lib64/ld-linux-x86-64.so.2"
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app":         namedELF(elf.EM_X86_64, elf.ELFCLASS64, interp, "", []string{"libfoo.so.1"}),
			interp:                 fixtureBody(cgoDynamicFixtureRoot(), cgoLoaderName, cgoLoaderSHA256),
			"/usr/lib/libfoo.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libfoo.so.1", nil),
		})

		edges, err := runtimeDependencies(fs, present)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ConsistOf("/usr/lib/libfoo.so.1", interp))
	})

	// A loader is the file its name leads to, and the name it answers to is the one
	// the executables wrote - not the name of whatever file the links end at.
	ginkgo.It("refuses a leaf link from the interpreter's name onto another library", func() {
		const interp = "/lib64/ld-linux-x86-64.so.2"
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app": namedELF(elf.EM_X86_64, elf.ELFCLASS64, interp, "", []string{"libc.so.6"}),
			// A library of the image's own, standing where the loader's name
			// leads: it answers to its own name and to no other.
			"/usr/lib/libc.so.6": loaderELF("libc.so.6", "/usr/lib/"),
		})
		fs.index.Symlinks[interp] = "/usr/lib/libc.so.6"

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"runtime loader SONAME mismatch /usr/lib/libc.so.6: it is named as ld-linux-x86-64.so.2 and calls itself libc.so.6")))
	})

	// The layout every glibc before 2.34 ships: the loader is `ld-2.31.so` and the
	// name the executables write points at it. It answers truly to the name it was
	// asked for, which is the only name anything asked of it.
	ginkgo.It("accepts a loader the image keeps under its versioned name", func() {
		const (
			interp = "/lib64/ld-linux-x86-64.so.2"
			held   = "/lib/x86_64-linux-gnu/ld-2.31.so"
		)
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app":         namedELF(elf.EM_X86_64, elf.ELFCLASS64, interp, "", []string{"libfoo.so.1"}),
			held:                   loaderELF("ld-linux-x86-64.so.2", "/usr/lib/"),
			"/usr/lib/libfoo.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libfoo.so.1", nil),
		})
		fs.index.Symlinks[interp] = held

		edges, err := runtimeDependencies(fs, present)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ConsistOf("/usr/lib/libfoo.so.1", held))
	})

	// A third layout, read out of a real loader rather than reasoned about: Debian's
	// multiarch, where four directories are searched and the order of them decides
	// which of two files answers a name. Sorting them would put /lib before
	// /lib/x86_64-linux-gnu and resolve to the wrong one.
	ginkgo.It("reads the four directories a Debian multiarch loader searches, in order", func() {
		root := os.Getenv("DK_DEBIAN_LOADER_FIXTURE")
		if root == "" {
			ginkgo.Skip("set DK_DEBIAN_LOADER_FIXTURE to a Debian /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
		}
		body, err := os.ReadFile(root)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		model, err := readLoaderModel(body, "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(model.dirs).To(gomega.Equal([]string{
			"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib",
		}))
		gomega.Expect(model.cache).To(gomega.Equal("/etc/ld.so.cache"))
	})

	// The cache is opened by path, and the image decides where a path leads.
	ginkgo.DescribeTable("refuses an image holding the cache its loader would read, however it is reached",
		func(ctx ginkgo.SpecContext, lay func(fs *filesystem)) {
			root := cgoDynamicFixtureRoot()
			fs, present := nativeFilesystem(map[string][]byte{
				"/usr/bin/git-lfs":              fixtureBody(root, cgoDynamicName, cgoDynamicSHA256),
				"/usr/lib/ld-linux-x86-64.so.2": fixtureBody(root, cgoLoaderName, cgoLoaderSHA256),
				"/usr/lib/libc.so.6":            fixtureBody(root, cgoLibcName, ""),
				"/usr/lib/libresolv.so.2":       fixtureBody(root, cgoResolvName, ""),
			})
			fs.index.Symlinks["/lib64"] = "/usr/lib"
			lay(fs)

			_, err := runtimeDependencies(fs, present)

			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
				"unsupported dynamic loader feature /etc/ld.so.cache")))
		},
		ginkgo.Entry("held where the loader names it", func(fs *filesystem) {
			fs.index.Files["/etc/ld.so.cache"] = shippedscope.File{}
		}),
		ginkgo.Entry("reached through a link of its own", func(fs *filesystem) {
			fs.index.Symlinks["/etc/ld.so.cache"] = "/var/cache/ld.so.cache"
			fs.index.Files["/var/cache/ld.so.cache"] = shippedscope.File{}
		}),
		ginkgo.Entry("standing in an /etc that is itself a link", func(fs *filesystem) {
			fs.index.Symlinks["/etc"] = "/usr/etc"
			fs.index.Files["/usr/etc/ld.so.cache"] = shippedscope.File{}
		}),
	)

	// The cache refused is the one this loader states, not the one at the path every
	// other loader happens to use.
	ginkgo.It("refuses the cache its own loader names, wherever that is", func() {
		const interp = "/lib64/ld-linux-x86-64.so.2"
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app":         namedELF(elf.EM_X86_64, elf.ELFCLASS64, interp, "", []string{"libfoo.so.1"}),
			interp:                 cachingLoaderELF("ld-linux-x86-64.so.2", "/usr/lib/", "/var/cache/ld.so.cache"),
			"/usr/lib/libfoo.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libfoo.so.1", nil),
		})
		fs.index.Files["/var/cache/ld.so.cache"] = shippedscope.File{}

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unsupported dynamic loader feature /var/cache/ld.so.cache")))
	})

	// A loader answers to every name it was asked for. Two executables may name it
	// differently, and a name it does not answer to is a file nobody described.
	ginkgo.It("asks a loader for every name the executables gave it", func() {
		const (
			right = "/lib64/ld-linux-x86-64.so.2"
			wrong = "/opt/toolchain/ld-musl-x86_64.so.1"
			held  = "/usr/lib/ld-linux-x86-64.so.2"
		)
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app":   namedELF(elf.EM_X86_64, elf.ELFCLASS64, right, "", nil),
			"/usr/bin/other": namedELF(elf.EM_X86_64, elf.ELFCLASS64, wrong, "", nil),
			held:             loaderELF("ld-linux-x86-64.so.2", "/usr/lib/"),
		})
		fs.index.Symlinks[right] = held
		fs.index.Symlinks[wrong] = held

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"runtime loader SONAME mismatch " + held + ": it is named as ld-musl-x86_64.so.1 and calls itself ld-linux-x86-64.so.2")))
	})

	// What a loader may rewrite as it runs, or holds as data of another kind, is not a
	// statement about the directories it was built to search.
	ginkgo.It("reads the search directories out of the loader's read-only data alone", func() {
		const interp = "/lib64/ld-linux-x86-64.so.2"
		body := elsewhereLoaderELF("ld-linux-x86-64.so.2", "/usr/lib/", []extraSection{
			{name: ".data.rel.ro", flags: elf.SHF_ALLOC | elf.SHF_WRITE, body: []byte("/rewritten/\x00")},
			{name: ".eh_frame", flags: elf.SHF_ALLOC, body: []byte("/unwound/\x00")},
			// Read-only by name and writable by flag: what it holds is what the
			// loader may rewrite, whatever the section is called.
			{name: ".rodata", flags: elf.SHF_ALLOC | elf.SHF_WRITE, body: []byte("/relro/\x00")},
		})

		model, err := readLoaderModel(body, interp)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(model.dirs).To(gomega.Equal([]string{"/usr/lib"}))
	})

	// The preload file is opened by path like any other.
	ginkgo.It("refuses an image whose preload file is reached through a link", func() {
		const interp = "/lib64/ld-linux-x86-64.so.2"
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/app":         namedELF(elf.EM_X86_64, elf.ELFCLASS64, interp, "", []string{"libfoo.so.1"}),
			interp:                 loaderELF("ld-linux-x86-64.so.2", "/usr/lib/"),
			"/usr/lib/libfoo.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libfoo.so.1", nil),
		})
		fs.index.Symlinks["/etc"] = "/usr/etc"
		fs.index.Files["/usr/etc/ld.so.preload"] = shippedscope.File{}

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unsupported dynamic loader feature /etc/ld.so.preload")))
	})

	// Shared objects alone name no interpreter, so nothing says where their own
	// dependencies would be looked for.
	ginkgo.It("refuses dynamic objects in an image where nothing names a loader", func() {
		root := cgoDynamicFixtureRoot()
		// libresolv names no interpreter of its own; glibc's libc does, so the
		// image left here holds nothing that says what runs it.
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/lib/libresolv.so.2": fixtureBody(root, cgoResolvName, ""),
		})

		_, err := runtimeDependencies(fs, present)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no executable of this image names a runtime loader")))
	})
})

var _ = ginkgo.Describe("What a dynamic cgo record says about the C it was linked with", func() {
	// A go-cgo-dynamic executable carries C compiled into it - the startup objects
	// and libc_nonshared among them - and those are not resolved at run time, so no
	// closure of this image could account for them. The record is what accounts for
	// them: the reader requires every input to state its kind, its disposition and
	// the components it brought, and refuses to call the composition known when any
	// of that is missing. So this gate adds no check of its own here; it reports
	// what the record states, and a record that cannot state it is not accepted.
	ginkgo.It("names the statically linked C objects among the record's inputs", func() {
		body := fixtureBody(cgoDynamicFixtureRoot(), cgoDynamicName, cgoDynamicSHA256)

		record, _, err := shared.ReadELFBuildRecord(bytes.NewReader(body))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		statics := map[string]shared.BuildInput{}
		for _, input := range record.Inputs {
			if strings.HasSuffix(input.Path, ".o") || strings.Contains(input.Path, "libc_nonshared") {
				statics[path.Base(input.Path)] = input
			}
		}
		gomega.Expect(statics).To(gomega.HaveKey("crt1.o"))
		gomega.Expect(statics).To(gomega.HaveKey("libc_nonshared.a"))
		for name, input := range statics {
			gomega.Expect(input.Kind).NotTo(gomega.BeEmpty(), name)
			gomega.Expect(input.Disposition).NotTo(gomega.BeEmpty(), name)
			gomega.Expect(input.Components).NotTo(gomega.BeNil(), name)
			gomega.Expect(input.Kind).NotTo(gomega.Equal("shared"), name)
		}
	})
})
