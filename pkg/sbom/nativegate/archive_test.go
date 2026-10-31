package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
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
// member's and carry no record.
func gnuSymbolTable() archiveEntry {
	return archiveEntry{name: "/", body: []byte{0, 0, 0, 0}}
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
				archiveEntry{name: "#1/16", body: append([]byte("__.SYMDEF SORTED"), 0, 0, 0, 0)},
				archiveEntry{name: fmt.Sprintf("#1/%d", len(name)), body: append(name, recordedMember("first-object")...)},
			)
		}),
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
		}, "invalid: the archive ends inside the header of member 0"),
		ginkgo.Entry("an archive cut inside a member", func() []byte {
			body := fixtureArchive(memberEntry("start", "first-object"))
			return body[:len(body)-8]
		}, "invalid: member 0 extends past the end of the archive"),
		ginkgo.Entry("a header stating no readable size", func() []byte {
			body := fixtureArchive(memberEntry("start", "first-object"))
			copy(body[len(archiveMagic)+48:], "xxxxxxxxxx")
			return body
		}, "invalid: the header of member 0 states no readable size"),
		ginkgo.Entry("a member header that is not terminated", func() []byte {
			body := fixtureArchive(memberEntry("start", "first-object"))
			body[len(archiveMagic)+58] = ' '
			return body
		}, "invalid: the header of member 0 is not terminated"),
		ginkgo.Entry("a long name no name table holds", func() []byte {
			return fixtureArchive(archiveEntry{name: "/17", body: recordedMember("first-object")})
		}, "invalid: an archive member names no entry of the archive's name table"),
	)

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
		}, `invalid: archive member "start" takes no distinct ordinal`),
		ginkgo.Entry("an archive carrying a record of its own", func(r *Record) {
			r.Composition = r.Archive.Members[0].Composition
		}, "invalid: an archive carries no build record of its own"),
	)
})
