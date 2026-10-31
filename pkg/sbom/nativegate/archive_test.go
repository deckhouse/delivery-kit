package nativegate

import (
	"bytes"
	"compress/gzip"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// archivePath is a static library of the strict C core: every member of it is a
// relocatable object the build recorded, and the archive itself is just how they
// are shipped together.
const archivePath = "/usr/lib/libc.a"

// archiveEntry is one member as an ar header spells it: the name field verbatim,
// so that a spec can write an index table as well as an ordinary member.
type archiveEntry struct {
	name string
	body []byte
}

func fixtureArchive(entries ...archiveEntry) []byte {
	ginkgo.GinkgoHelper()
	out := bytes.NewBufferString(archiveMagic)
	for _, entry := range entries {
		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", entry.name, 0, 0, 0, 0o644, len(entry.body))
		gomega.Expect(header).To(gomega.HaveLen(archiveHeaderLen))
		_, err := out.WriteString(header)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = out.Write(entry.body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		if len(entry.body)%2 == 1 {
			gomega.Expect(out.WriteByte('\n')).To(gomega.Succeed())
		}
	}

	return out.Bytes()
}

// recordedMember is a relocatable object carrying its own complete record, told
// apart from the next one by the component that record names. The identity of a
// component is its source rather than its name, so both move together.
func recordedMember(component string) []byte {
	record := fixtureBuildRecord(elf.ET_REL)
	record.Components[0].Name = component
	record.Components[0].Source.Locator = "https://example.invalid/" + component

	return runtimeELFWithRecord(elf.ET_REL, record)
}

func memberEntry(name, component string) archiveEntry {
	return archiveEntry{name: name + "/", body: recordedMember(component)}
}

// gnuSymbolTable is the index a linker reads names out of; its bytes are no
// member's and carry no record. This one publishes nothing.
func gnuSymbolTable() archiveEntry {
	return archiveEntry{name: "/", body: []byte{0, 0, 0, 0}}
}

// bsdSymbolTable is the same table in the ranlib form of a BSD archive: an
// empty symbol array and an empty string table behind it.
func bsdSymbolTable(name string) archiveEntry {
	return archiveEntry{name: fmt.Sprintf("#1/%d", len(name)), body: append([]byte(name), make([]byte, 8)...)}
}

// archiveHeaderOffsets is where each entry's header stands in the archive those
// entries make, which is what the symbol index of a real archive points at.
func archiveHeaderOffsets(entries []archiveEntry) []int {
	offsets := []int{}
	at := len(archiveMagic)
	for _, entry := range entries {
		offsets = append(offsets, at)
		at += archiveHeaderLen + len(entry.body) + len(entry.body)%2
	}

	return offsets
}

// ranlibArchive writes the BSD form of the same thing: a ranlib table of one
// symbol standing at the member's header, in the byte order of the host that
// wrote it, with offset replacing that of the member when it is given.
func ranlibArchive(order binary.ByteOrder, offset int) []byte {
	ginkgo.GinkgoHelper()
	names := append([]byte("symbol0"), 0)
	armap := make([]byte, 16+len(names))
	order.PutUint32(armap, 8)
	order.PutUint32(armap[12:], uint32(len(names)))
	copy(armap[16:], names)
	member := memberEntry("start", "first-object")
	entries := []archiveEntry{{name: "__.SYMDEF", body: armap}, member}
	if offset == 0 {
		offset = archiveHeaderOffsets(entries)[1]
	}
	order.PutUint32(armap[8:], uint32(offset))

	return fixtureArchive(entries...)
}

// armapArchive writes an archive of one member whose armap publishes count
// symbols at that member's header, holds the given names and carries tail
// behind them. It is how a spec states an index that does not add up.
func armapArchive(count int, names, tail []byte) []byte {
	armap := make([]byte, 4+4*count+len(names)+len(tail))
	binary.BigEndian.PutUint32(armap, uint32(count))
	copy(armap[4+4*count:], names)
	copy(armap[4+4*count+len(names):], tail)
	member := memberEntry("start", "first-object")
	offset := archiveHeaderOffsets([]archiveEntry{{name: "/", body: armap}, member})[1]
	for n := 0; n < count; n++ {
		binary.BigEndian.PutUint32(armap[4+4*n:], uint32(offset))
	}

	return fixtureArchive(archiveEntry{name: "/", body: armap}, member)
}

// indexedArchive is the archive a linker is given: an armap publishing one
// symbol per member, at the offset of that member's own header.
func indexedArchive(members ...archiveEntry) []byte {
	ginkgo.GinkgoHelper()
	var names bytes.Buffer
	for position := range members {
		_, err := fmt.Fprintf(&names, "symbol%d\x00", position)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	armap := make([]byte, 4+4*len(members))
	binary.BigEndian.PutUint32(armap, uint32(len(members)))
	entries := append([]archiveEntry{{name: "/", body: append(armap, names.Bytes()...)}}, members...)
	for position, offset := range archiveHeaderOffsets(entries)[1:] {
		binary.BigEndian.PutUint32(entries[0].body[4+4*position:], uint32(offset))
	}

	return fixtureArchive(entries...)
}

func archiveCatalog(bom *cdx.BOM) Catalog {
	ginkgo.GinkgoHelper()
	catalog, err := ReadCatalog([]*cdx.BOM{bom})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(catalog.Records).To(gomega.HaveLen(1))

	return catalog
}

func archiveRecord(bom *cdx.BOM) Record {
	ginkgo.GinkgoHelper()

	return archiveCatalog(bom).Records[0]
}

func applyArchive(body []byte) (*cdx.BOM, error) {
	bom := cdx.NewBOM()

	return bom, Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{archivePath: string(body)}), nil, bom)
}

// The archives under testdata/archives are what the gcc:13 image ships, taken
// as they are: libssp_nonshared.a and libuuid.a from binutils ar 2.40 and
// libevent_openssl.a from a Debian build of the same. Each declares a name
// table whose names come to an odd number of bytes, which is the case bfd pads
// with a newline of its own. Beside each, the members `ar t` reports.
func realArchive(name string) []byte {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(filepath.Join("testdata", "archives", name+".gz"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	reader, err := gzip.NewReader(bytes.NewReader(body))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	body, err = io.ReadAll(reader)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return body
}

func realArchiveNames(name string) []string {
	ginkgo.GinkgoHelper()
	listed, err := os.ReadFile(filepath.Join("testdata", "archives", name+".members"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return strings.Fields(string(listed))
}

var _ = ginkgo.Describe("shipped static archive", func() {
	ginkgo.It("accepts an archive whose every member carries its own record and is made of what they are", func() {
		body := fixtureArchive(gnuSymbolTable(), memberEntry("start", "first-object"), memberEntry("printf", "second-object"))

		bom, err := applyArchive(body)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		catalog := archiveCatalog(bom)
		record := catalog.Records[0]
		// The archive states no record of its own: the contract gives it no
		// artifact kind, and its composition is the members'.
		gomega.Expect(record.Composition).To(gomega.BeEmpty())
		gomega.Expect(record.Components).To(gomega.HaveLen(2))
		gomega.Expect(record.Archive.Members).To(gomega.HaveLen(2))
		names := []string{}
		for position, member := range record.Archive.Members {
			gomega.Expect(member.Index).To(gomega.Equal(position), "the symbol table takes no ordinal")
			gomega.Expect(member.Profile).To(gomega.Equal("c-object"))
			gomega.Expect(record.Components).To(gomega.ContainElements(member.Components))
			names = append(names, member.Name)
		}
		gomega.Expect(names).To(gomega.Equal([]string{"start", "printf"}))
		gomega.Expect(record.Archive.Members[0].SHA256).To(gomega.Equal(digest(recordedMember("first-object"))))
		var composition shared.BuildRecord
		gomega.Expect(json.Unmarshal(record.Archive.Members[1].Composition, &composition)).To(gomega.Succeed())
		gomega.Expect(composition.Artifact).To(gomega.Equal("object"))
		gomega.Expect(composition.Components[0].Name).To(gomega.Equal("second-object"))
		components := []string{}
		for _, ref := range record.Components {
			components = append(components, catalog.Components[ref].Name)
		}
		gomega.Expect(components).To(gomega.ConsistOf("first-object", "second-object"))
	})

	// glibc installs libdl.a, libpthread.a, librt.a, libanl.a and libutil.a as
	// archives holding nothing at all. Such a file ships no code, and saying so
	// is what keeps it from being content nobody accounted for.
	ginkgo.It("accepts a memberless archive and credits it with nothing", func() {
		bom, err := applyArchive(fixtureArchive(gnuSymbolTable()))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := archiveRecord(bom)
		gomega.Expect(record.Path).To(gomega.Equal(archivePath))
		gomega.Expect(record.Components).To(gomega.BeEmpty())
		gomega.Expect(record.Archive).NotTo(gomega.BeNil())
		gomega.Expect(record.Archive.Members).To(gomega.BeEmpty())
	})

	// A name is no identity: which member a link selects is settled by the
	// ordinal, and both of these answer for themselves.
	ginkgo.It("reads two members of one name as the two members they are", func() {
		first, second := recordedMember("first-object"), recordedMember("second-object")
		body := fixtureArchive(archiveEntry{name: "dup.o/", body: first}, archiveEntry{name: "dup.o/", body: second})

		bom, err := applyArchive(body)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := archiveRecord(bom)
		gomega.Expect(record.Components).To(gomega.HaveLen(2))
		gomega.Expect(record.Archive.Members).To(gomega.HaveLen(2))
		gomega.Expect(record.Archive.Members[0]).To(gomega.HaveField("Name", "dup.o"))
		gomega.Expect(record.Archive.Members[1]).To(gomega.HaveField("Name", "dup.o"))
		gomega.Expect(record.Archive.Members[0].SHA256).To(gomega.Equal(digest(first)))
		gomega.Expect(record.Archive.Members[1].SHA256).To(gomega.Equal(digest(second)))
	})

	// A long name lives in a table of its own in either flavor of ar, and the
	// BSD symbol table is an ordinary member by its header alone.
	ginkgo.DescribeTable("reads the member a long name states", func(build func() []byte) {
		bom, err := applyArchive(build())

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := archiveRecord(bom)
		gomega.Expect(record.Archive.Members).To(gomega.HaveLen(1))
		gomega.Expect(record.Archive.Members[0].Name).To(gomega.Equal("a-very-long-member-name.o"))
		gomega.Expect(record.Components).To(gomega.HaveLen(1))
	},
		ginkgo.Entry("out of the GNU name table", func() []byte {
			return fixtureArchive(
				archiveEntry{name: "//", body: []byte("a-very-long-member-name.o/\n")},
				archiveEntry{name: "/0", body: recordedMember("first-object")},
			)
		}),
		ginkgo.Entry("out of the BSD member's own bytes", func() []byte {
			name := append([]byte("a-very-long-member-name.o"), 0, 0, 0)
			return fixtureArchive(
				bsdSymbolTable("__.SYMDEF SORTED"),
				archiveEntry{name: fmt.Sprintf("#1/%d", len(name)), body: append(name, recordedMember("first-object")...)},
			)
		}),
	)

	// A library a strict image ships is the archive bfd wrote, and this reader
	// has to name the members `ar t` names in it.
	ginkgo.DescribeTable("reads an archive binutils wrote as the members ar reports", func(name string) {
		members, err := archiveMembers(realArchive(name))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		names := []string{}
		for _, member := range members {
			names = append(names, member.name)
		}
		gomega.Expect(names).To(gomega.Equal(realArchiveNames(name)))
	},
		ginkgo.Entry("libssp_nonshared.a", "libssp_nonshared.a"),
		ginkgo.Entry("libuuid.a", "libuuid.a"),
		ginkgo.Entry("libevent_openssl.a", "libevent_openssl.a"),
	)

	// bfd declares the name table an even number of bytes and pads it with a
	// newline of its own when the names come to an odd number. That byte is the
	// table's; anything else behind the last name is content it does not hold.
	ginkgo.DescribeTable("reads the newline bfd pads an odd name table with", func(table string, expected string) {
		_, err := applyArchive(fixtureArchive(
			archiveEntry{name: "//", body: []byte(table)},
			archiveEntry{name: "/0", body: recordedMember("first-object")},
		))

		if expected == "" {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			return
		}
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("behind names of an odd length", "a-very-long-member-name.o/\n\n", ""),
		ginkgo.Entry("behind names of an even length", "a-long-member-name.o/\n\n", "invalid: the archive's name table holds something other than the names of its members"),
		ginkgo.Entry("twice behind names of an odd length", "a-very-long-member-name.o/\n\n\n", "invalid: the archive's name table holds something other than the names of its members"),
		ginkgo.Entry("as a byte of its own", "a-very-long-member-name.o/\nx", "invalid: the archive's name table holds something other than the names of its members"),
	)

	// ar left-justifies the name in its field and pads it with spaces behind, so
	// the name of this member is the one with the space in front of it.
	ginkgo.It("reads a name the header field does not left-justify as it stands", func() {
		bom, err := applyArchive(fixtureArchive(archiveEntry{name: " start/", body: recordedMember("first-object")}))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(archiveRecord(bom).Archive.Members[0].Name).To(gomega.Equal(" start"))
	})

	// A symbol index is published under a name of the header field alone. Taking
	// one out of a long name would read the table of an archive out of bytes a
	// member holds, and leave that member unaccounted for.
	ginkgo.It("refuses a long name spelling the name of a symbol index", func() {
		_, err := applyArchive(fixtureArchive(archiveEntry{
			name: "#1/8", body: append([]byte("/SYM64/\x00"), recordedMember("first-object")...),
		}))

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: entry 0 spells a long name that names no member")))
	})

	// An archive a linker is given publishes its members through an armap, and
	// what that armap says has to be what the archive holds.
	ginkgo.It("accepts an archive whose index publishes its members", func() {
		bom, err := applyArchive(indexedArchive(memberEntry("start", "first-object"), memberEntry("printf", "second-object")))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := archiveRecord(bom)
		gomega.Expect(record.Archive.Members).To(gomega.HaveLen(2))
		gomega.Expect(record.Components).To(gomega.HaveLen(2))
	})

	// A BSD ranlib table is written in the byte order of the host that wrote it,
	// and nothing in the archive says which that was: the reading under which
	// the symbols stand at member headers is the one that is real.
	ginkgo.DescribeTable("reads a BSD index in the byte order it was written in", func(order binary.ByteOrder) {
		bom, err := applyArchive(ranlibArchive(order, 0))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(archiveRecord(bom).Archive.Members).To(gomega.HaveLen(1))
	},
		ginkgo.Entry("little endian", binary.ByteOrder(binary.LittleEndian)),
		ginkgo.Entry("big endian", binary.ByteOrder(binary.BigEndian)),
	)

	// Neither reading of this table stands at a member: the one it was written
	// in publishes a symbol inside the table itself, and under the other the
	// table does not even read as one.
	ginkgo.It("refuses a BSD index whose symbols stand at no member in either order", func() {
		_, err := applyArchive(ranlibArchive(binary.LittleEndian, len(archiveMagic)+archiveHeaderLen))

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: the archive index")))
	})

	// ar writes an armap of no bytes for an archive that publishes nothing.
	ginkgo.It("accepts an archive whose index holds nothing", func() {
		bom, err := applyArchive(fixtureArchive(archiveEntry{name: "/"}, memberEntry("start", "first-object")))

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(archiveRecord(bom).Archive.Members).To(gomega.HaveLen(1))
	})

	// bfd reads the symbol index as the first entry of an archive and the name
	// table before the members that spell their names through it. A header
	// carrying one of those names anywhere else is an ordinary member to it,
	// linked under --whole-archive and under any symbol the index publishes for
	// it, so skipping such a header as bookkeeping would hide a member.
	ginkgo.DescribeTable("refuses an index table standing where no linker reads one", func(build func() []byte, expected string) {
		_, err := applyArchive(build())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("a GNU armap behind a member", func() []byte {
			return fixtureArchive(memberEntry("start", "first-object"), archiveEntry{name: "/", body: []byte{0, 0, 0, 0}})
		}, "invalid: index table out of place, entry 1"),
		ginkgo.Entry("a 64-bit armap behind a member", func() []byte {
			return fixtureArchive(memberEntry("start", "first-object"), archiveEntry{name: "/SYM64/", body: make([]byte, 8)})
		}, "invalid: index table out of place, entry 1"),
		ginkgo.Entry("a ranlib table behind a member", func() []byte {
			return fixtureArchive(memberEntry("start", "first-object"), bsdSymbolTable("__.SYMDEF"))
		}, "invalid: index table out of place, entry 1"),
		ginkgo.Entry("a ranlib table under its GNU spelling behind a member", func() []byte {
			return fixtureArchive(memberEntry("start", "first-object"), archiveEntry{name: "__.SYMDEF/", body: make([]byte, 8)})
		}, "invalid: index table out of place, entry 1"),
		ginkgo.Entry("a second armap behind the first", func() []byte {
			return fixtureArchive(gnuSymbolTable(), archiveEntry{name: "/", body: []byte{0, 0, 0, 0}}, memberEntry("start", "first-object"))
		}, "invalid: index table out of place, entry 1"),
		ginkgo.Entry("a name table behind a member", func() []byte {
			return fixtureArchive(
				memberEntry("start", "first-object"),
				archiveEntry{name: "//", body: []byte("a-very-long-member-name.o/\n")},
				archiveEntry{name: "/0", body: recordedMember("second-object")},
			)
		}, "invalid: index table out of place, entry 1"),
		ginkgo.Entry("a second name table", func() []byte {
			return fixtureArchive(
				archiveEntry{name: "//", body: []byte("a-very-long-member-name.o/\n")},
				archiveEntry{name: "//", body: []byte("another-long-member-name.o/\n")},
				archiveEntry{name: "/0", body: recordedMember("first-object")},
			)
		}, "invalid: index table out of place, entry 1"),
	)

	// The armap is read the way `ld -u` reads it: a symbol stands at an offset,
	// and whatever member's header is there gets linked. An offset pointing into
	// the armap itself, at a header and an object written inside it, would link
	// bytes no reading of the members ever saw.
	ginkgo.DescribeTable("refuses an index publishing what the archive does not hold", func(build func() []byte, expected string) {
		_, err := applyArchive(build())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("a symbol standing inside the index itself", func() []byte {
			hidden := fixtureArchive(archiveEntry{name: "hidden.o/", body: recordedMember("hidden-object")})[len(archiveMagic):]
			armap := make([]byte, 8+len("hidden\x00"))
			binary.BigEndian.PutUint32(armap, 1)
			copy(armap[8:], "hidden\x00")
			// The hidden header stands behind the symbol it is published under,
			// inside the bytes of the armap member.
			binary.BigEndian.PutUint32(armap[4:], uint32(len(archiveMagic)+archiveHeaderLen+len(armap)))
			return fixtureArchive(archiveEntry{name: "/", body: append(armap, hidden...)}, memberEntry("start", "first-object"))
		}, "where no member of the archive stands"),
		ginkgo.Entry("a symbol of an archive holding no member", func() []byte {
			armap := make([]byte, 8+len("hidden\x00"))
			binary.BigEndian.PutUint32(armap, 1)
			binary.BigEndian.PutUint32(armap[4:], uint32(len(archiveMagic)))
			copy(armap[8:], "hidden\x00")
			return fixtureArchive(archiveEntry{name: "/", body: armap})
		}, "where no member of the archive stands"),
		ginkgo.Entry("a symbol standing between two members", func() []byte {
			body := indexedArchive(memberEntry("start", "first-object"), memberEntry("printf", "second-object"))
			binary.BigEndian.PutUint32(body[len(archiveMagic)+archiveHeaderLen+4:], uint32(len(archiveMagic)+archiveHeaderLen))
			return body
		}, "where no member of the archive stands"),
		ginkgo.Entry("an index publishing more symbols than it names", func() []byte {
			return armapArchive(2, append([]byte("symbol0"), 0), nil)
		}, "invalid: the archive index publishes 2 symbols and holds 1 names"),
		ginkgo.Entry("an index carrying bytes behind its names", func() []byte {
			return armapArchive(1, append([]byte("symbol0"), 0), []byte("x"))
		}, "invalid: the archive index carries bytes behind the symbol names it publishes"),
		ginkgo.Entry("a name table holding something other than names", func() []byte {
			return fixtureArchive(
				archiveEntry{name: "//", body: []byte("a-very-long-member-name.o\n")},
				archiveEntry{name: "/0", body: recordedMember("first-object")},
			)
		}, "invalid: the archive's name table holds something other than the names of its members"),
		ginkgo.Entry("a long name standing inside another name", func() []byte {
			return fixtureArchive(
				archiveEntry{name: "//", body: []byte("a-very-long-member-name.o/\n")},
				archiveEntry{name: "/2", body: recordedMember("first-object")},
			)
		}, "invalid: entry 1 names no entry of the archive's name table"),
		// bfd spells the offset of a long name as decimal digits alone, so a signed
		// one names no entry of the table even where it reads as a number.
		ginkgo.Entry("a long name offset carrying a plus", func() []byte {
			return fixtureArchive(
				archiveEntry{name: "//", body: []byte("abc.o/\n\n")},
				archiveEntry{name: "/+0", body: recordedMember("first-object")},
			)
		}, "invalid: entry 1 names no entry of the archive's name table"),
		ginkgo.Entry("a long name offset carrying a minus", func() []byte {
			return fixtureArchive(
				archiveEntry{name: "//", body: []byte("abc.o/\n\n")},
				archiveEntry{name: "/-0", body: recordedMember("first-object")},
			)
		}, "invalid: entry 1 names no entry of the archive's name table"),
	)

	ginkgo.DescribeTable("refuses an archive a member of which answers for nothing", func(build func() []byte, expected string) {
		_, err := applyArchive(build())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		// The replacement name is as long as the original, so nothing but the
		// section's identity changes.
		ginkgo.Entry("a member carrying no record", func() []byte {
			unrecorded := bytes.Replace(recordedMember("first-object"), []byte(".note.package"), []byte(".note.unknown"), 1)
			return fixtureArchive(memberEntry("start", "first-object"), archiveEntry{name: "printf/", body: unrecorded})
		}, "no-data: missing sbom metadata (archive member printf, index 1)"),
		ginkgo.Entry("a member whose record is incomplete", func() []byte {
			return fixtureArchive(archiveEntry{name: "start/", body: runtimeELFWithRecord(elf.ET_REL, partialRecord(elf.ET_REL))})
		}, "missing property 'tools' (archive member start, index 0)"),
		ginkgo.Entry("a member whose record is another container's", func() []byte {
			return fixtureArchive(archiveEntry{name: "start/", body: runtimeELFWithRecord(elf.ET_REL, fixtureBuildRecord(elf.ET_EXEC))})
		}, `invalid: artifact "elf" does not match ELF type ET_REL (archive member start, index 0)`),
		ginkgo.Entry("a member that is no object at all", func() []byte {
			return fixtureArchive(memberEntry("start", "first-object"), archiveEntry{name: "notes.txt/", body: []byte("just text\n")})
		}, "no-data: archive member notes.txt (index 1) is no relocatable object carrying a record of its build"),
		ginkgo.Entry("a member that is an executable rather than an object", func() []byte {
			return fixtureArchive(archiveEntry{name: "tool/", body: minimalRuntimeELF(elf.ET_EXEC)})
		}, "no-data: archive member tool (index 0) is no relocatable object carrying a record of its build"),
		ginkgo.Entry("a member that is an archive of its own", func() []byte {
			return fixtureArchive(archiveEntry{name: "inner.a/", body: fixtureArchive(memberEntry("start", "first-object"))})
		}, "no-data: archive member inner.a (index 0) is no relocatable object carrying a record of its build"),
	)

	ginkgo.DescribeTable("refuses bytes that do not read as an archive of members", func(build func() []byte, expected string) {
		_, err := applyArchive(build())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		// A thin archive holds the names of files outside it, and this gate
		// reads a composition out of bytes rather than out of a reference.
		ginkgo.Entry("a thin archive", func() []byte {
			return append([]byte(thinArchiveMagic), fixtureArchive(memberEntry("start", "first-object"))[len(archiveMagic):]...)
		}, "unsupported: a thin archive holds no member bytes"),
		ginkgo.Entry("an archive cut inside a member header", func() []byte {
			return fixtureArchive(memberEntry("start", "first-object"))[:len(archiveMagic)+20]
		}, "invalid: the archive ends inside the header of entry 0"),
		ginkgo.Entry("an archive cut inside a member", func() []byte {
			body := fixtureArchive(memberEntry("start", "first-object"))
			return body[:len(body)-8]
		}, "invalid: entry 0 extends past the end of the archive"),
		ginkgo.Entry("a header stating no readable size", func() []byte {
			body := fixtureArchive(memberEntry("start", "first-object"))
			copy(body[len(archiveMagic)+48:], "xxxxxxxxxx")
			return body
		}, "invalid: the header of entry 0 states no readable size"),
		ginkgo.Entry("a member header that is not terminated", func() []byte {
			body := fixtureArchive(memberEntry("start", "first-object"))
			body[len(archiveMagic)+58] = ' '
			return body
		}, "invalid: the header of entry 0 is not terminated"),
		ginkgo.Entry("a long name no name table holds", func() []byte {
			return fixtureArchive(archiveEntry{name: "/17", body: recordedMember("first-object")})
		}, "invalid: entry 0 names no entry of the archive's name table"),
	)

	// The byte that aligns an odd-sized member on an even boundary belongs to no
	// member: ar writes a newline there and go tool pack a NUL. Anything else is
	// content this reader does not account for.
	ginkgo.DescribeTable("reads the byte that aligns an odd-sized member as the padding it is", func(pad byte, expected string) {
		member := memberEntry("start", "first-object")
		gomega.Expect(len(member.body)%2).To(gomega.Equal(1), "the member this spec aligns is odd-sized")
		body := fixtureArchive(member)
		body[len(archiveMagic)+archiveHeaderLen+len(member.body)] = pad

		_, err := applyArchive(body)

		if expected == "" {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			return
		}
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("the newline ar writes", byte('\n'), ""),
		ginkgo.Entry("the NUL go tool pack writes", byte(0), ""),
		ginkgo.Entry("a byte of its own", byte('x'), "invalid: entry 0 is not followed by the padding an odd-sized member takes"),
	)

	// The record form an archive takes is the catalog's, and the version it is
	// published under says which form a reader is being handed.
	ginkgo.It("refuses the catalog version that knew no archive", func() {
		bom, err := applyArchive(fixtureArchive(memberEntry("start", "first-object")))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		old := cdx.NewBOM()
		catalog := archiveCatalog(bom)
		catalog.Schema = "dk.catalog/v4"
		gomega.Expect(catalog.attach(old)).To(gomega.Succeed())

		_, err = ReadCatalog([]*cdx.BOM{old})

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`unsupported inherited catalog "dk.catalog/v4"`)))
	})

	ginkgo.It("refuses a member whose profile the policy does not allow", func() {
		policy := objectPolicy()
		policy.Profiles = []string{"c-static"}

		err := Apply(context.Background(), policy, "image", fixtureImage(map[string]string{
			archivePath: string(fixtureArchive(memberEntry("start", "first-object"))),
		}), nil, cdx.NewBOM())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"unsupported: build profile c-object (archive member start, index 0)")))
	})

	// What was proven of an archive was proven of its bytes. Another archive at
	// that path, however its members answer for themselves, is not that file.
	ginkgo.It("refuses an inherited record whose bytes are another archive's", func() {
		first, err := applyArchive(fixtureArchive(memberEntry("start", "first-object")))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		other := fixtureArchive(memberEntry("start", "second-object"))

		err = Apply(context.Background(), objectPolicy(), "image", fixtureImage(map[string]string{archivePath: string(other)}), []*cdx.BOM{first}, cdx.NewBOM())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch: known file content changed " + archivePath)))
	})

	// What an archive record states was read out of the bytes of an archive. A
	// file bound to that record by digest alone and holding something else is
	// not that archive, and taking the record for it would credit a text file
	// with the composition of members it does not hold.
	ginkgo.It("refuses an inherited archive record bound to a file that is no archive", func() {
		bom, err := applyArchive(fixtureArchive(gnuSymbolTable()))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		catalog := archiveCatalog(bom)
		notes := "just text\n"
		catalog.Records[0].Path = "/usr/share/doc/notes.txt"
		catalog.Records[0].SHA256 = digest([]byte(notes))
		inherited := cdx.NewBOM()
		gomega.Expect(catalog.attach(inherited)).To(gomega.Succeed())

		err = Apply(context.Background(), objectPolicy(), "image",
			fixtureImage(map[string]string{catalog.Records[0].Path: notes}), []*cdx.BOM{inherited}, cdx.NewBOM())

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: recorded native composition does not match file")))
	})

	// An archive is made of its members and nothing else. A component standing
	// in the record that no member of the archive brought is attribution the
	// reading of the file never produced.
	ginkgo.It("refuses an inherited archive credited with a component no member of it holds", func() {
		bom, err := applyArchive(fixtureArchive(memberEntry("start", "first-object")))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		catalog := archiveCatalog(bom)
		elsewhere := cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: "urn:dk:component:elsewhere",
			Name: "elsewhere", Version: "1", PackageURL: "pkg:generic/elsewhere@1",
		}
		catalog.Components[elsewhere.BOMRef] = elsewhere
		catalog.Records[0].Components = append(catalog.Records[0].Components, elsewhere.BOMRef)
		damaged := cdx.NewBOM()
		gomega.Expect(catalog.attach(damaged)).To(gomega.Succeed())

		_, err = ReadCatalog([]*cdx.BOM{damaged})

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"invalid: the archive is credited with component urn:dk:component:elsewhere no member of it holds")))
	})

	// The catalog carries what was read, and a build inheriting it is held to
	// the same statement: a member crediting the archive with a component the
	// archive does not hold is a document no consumer can resolve.
	ginkgo.DescribeTable("refuses an inherited archive record that states what no reading of one could", func(damage func(*Record), expected string) {
		bom, err := applyArchive(fixtureArchive(memberEntry("start", "first-object")))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		catalog, err := ReadCatalog([]*cdx.BOM{bom})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		damage(&catalog.Records[0])
		damaged := cdx.NewBOM()
		gomega.Expect(catalog.attach(damaged)).To(gomega.Succeed())

		_, err = ReadCatalog([]*cdx.BOM{damaged})

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("a member of no identified bytes", func(r *Record) {
			r.Archive.Members[0].SHA256 = "sha256:" + strings.Repeat("z", 64)
		}, `invalid: archive member "start" states no identified content`),
		ginkgo.Entry("a member of no composition", func(r *Record) {
			r.Archive.Members[0].Composition = nil
		}, `no-data: missing inherited composition of archive member "start"`),
		ginkgo.Entry("a member whose profile disagrees with its composition", func(r *Record) {
			r.Archive.Members[0].Profile = "c-static"
		}, `invalid: inherited profile of archive member "start" disagrees with its composition`),
		ginkgo.Entry("a member crediting the archive with a component it does not hold", func(r *Record) {
			r.Archive.Members[0].Components = []string{"urn:dk:component:elsewhere"}
		}, `invalid: archive member "start" holds component urn:dk:component:elsewhere the archive is not credited with`),
		ginkgo.Entry("two members of one ordinal", func(r *Record) {
			r.Archive.Members = append(r.Archive.Members, r.Archive.Members[0])
		}, `invalid: archive member "start" does not take the ordinal of its place among the members`),
		ginkgo.Entry("a member standing at an ordinal the archive skipped", func(r *Record) {
			r.Archive.Members[0].Index = 1
		}, `invalid: archive member "start" does not take the ordinal of its place among the members`),

		ginkgo.Entry("an archive carrying a record of its own", func(r *Record) {
			r.Composition = r.Archive.Members[0].Composition
		}, "invalid: an archive carries no build record of its own"),
	)
})
