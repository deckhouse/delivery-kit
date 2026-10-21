package shippedscope

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = Describe("RecordOccurrences", func() {
	componentOf := func(purl string) cdx.Component {
		return cdx.Component{BOMRef: purl, Name: purl, PackageURL: purl}
	}

	bomOf := func(purls ...string) *cdx.BOM {
		components := make([]cdx.Component, 0, len(purls))
		for _, purl := range purls {
			components = append(components, componentOf(purl))
		}

		return &cdx.BOM{Components: &components}
	}

	occurrencesOf := func(bom *cdx.BOM, index int) []cdx.EvidenceOccurrence {
		comp := (*bom.Components)[index]
		if comp.Evidence == nil {
			return nil
		}

		return lo.FromPtr(comp.Evidence.Occurrences)
	}

	fileset := func(ecosystem Ecosystem, name, version string, files, symlinks map[string]string) Fileset {
		entries := make(map[string]File, len(files))
		for file, body := range files {
			entries[file] = File{Digest: digestOf(body), Size: int64(len(body))}
		}

		return Fileset{
			Ecosystem:     ecosystem,
			Name:          name,
			Version:       version,
			Files:         entries,
			Symlinks:      symlinks,
			DeclaresFiles: true,
		}
	}

	It("records the files of a component of each ecosystem", func() {
		bom := bomOf(
			"pkg:generic/zlib@1.3.1?containerfactoryversion=1",
			"pkg:pypi/requests@2.32.3",
			"pkg:npm/debug@4.3.4",
			"pkg:luarocks/luasocket@3.1.0-1",
		)

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1", map[string]string{"/usr/lib/libz.so.1.3.1": "z"}, nil),
			fileset(EcosystemPython, "requests", "2.32.3", map[string]string{"/usr/lib/python3/requests/__init__.py": "r"}, nil),
			fileset(EcosystemJavaScript, "debug", "4.3.4", map[string]string{"/app/node_modules/debug/index.js": "d"}, nil),
			fileset(EcosystemLua, "luasocket", "3.1.0-1", map[string]string{"/usr/lib/lua/socket/core.so": "l"}, nil),
		})

		Expect(recorded).To(Equal(4))
		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/libz.so.1.3.1", AdditionalContext: digestOf("z")},
		}))
		Expect(occurrencesOf(bom, 1)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("r")},
		}))
		Expect(occurrencesOf(bom, 2)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/app/node_modules/debug/index.js", AdditionalContext: digestOf("d")},
		}))
		Expect(occurrencesOf(bom, 3)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/lua/socket/core.so", AdditionalContext: digestOf("l")},
		}))
	})

	It("marks a symlink as one instead of leaving it to be told apart by a missing digest", func() {
		bom := bomOf("pkg:generic/zlib@1.3.1")

		RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1",
				map[string]string{"/usr/lib/libz.so.1.3.1": "z"},
				map[string]string{"/usr/lib/libz.so.1": "libz.so.1.3.1"},
			),
		})

		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/libz.so.1", AdditionalContext: "symlink"},
			{Location: "/usr/lib/libz.so.1.3.1", AdditionalContext: digestOf("z")},
		}))
	})

	It("leaves a component that declares no files alone, instead of saying none were found", func() {
		bom := bomOf("pkg:generic/build-essential@12.9")

		recorded := RecordOccurrences(bom, []Fileset{
			{Ecosystem: EcosystemOSPM, Name: "build-essential", Version: "12.9"},
		})

		Expect(recorded).To(BeZero())
		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("keeps what a donor recorded when the image holds none of the files its manifest declares", func() {
		bom := bomOf("pkg:pypi/requests@2.32.3")
		(*bom.Components)[0].Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("r")},
		}}

		recorded := RecordOccurrences(bom, []Fileset{{
			Ecosystem:     EcosystemPython,
			Name:          "requests",
			Version:       "2.32.3",
			DeclaresFiles: true,
		}})

		Expect(recorded).To(BeZero())
		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("r")},
		}), "the digests a donor recorded are the only way left to find the bytes this image moved")
	})

	It("says the files were looked for when the image holds no declared file of a component no donor described", func() {
		bom := bomOf("pkg:pypi/requests@2.32.3")

		recorded := RecordOccurrences(bom, []Fileset{{
			Ecosystem:     EcosystemPython,
			Name:          "requests",
			Version:       "2.32.3",
			DeclaresFiles: true,
		}})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{}),
			"a package the image installed and then deleted looks exactly like this, and nothing else could show its files")
	})

	It("says the files were looked for after the SBOM has been written and read back", func() {
		bom := bomOf("pkg:pypi/requests@2.32.3")

		Expect(RecordOccurrences(bom, []Fileset{{
			Ecosystem:     EcosystemPython,
			Name:          "requests",
			Version:       "2.32.3",
			DeclaresFiles: true,
		}})).To(Equal(1))

		data, err := cyclonedxutil.ToJSON(bom)
		Expect(err).NotTo(HaveOccurred())
		read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		Expect(err).NotTo(HaveOccurred())

		Expect(recordedOccurrences(&(*read.Components)[0])).To(Equal([]Occurrence{}),
			"an empty occurrence list does not survive serialization, so what it said has to")
	})

	It("keeps the verdict that no file was found through a merge of two documents", func() {
		bom := bomOf("pkg:pypi/requests@2.32.3")
		Expect(RecordOccurrences(bom, []Fileset{{
			Ecosystem:     EcosystemPython,
			Name:          "requests",
			Version:       "2.32.3",
			DeclaresFiles: true,
		}})).To(Equal(1))

		*bom.Components = append(*bom.Components, componentOf("pkg:pypi/requests@2.32.3"))
		cyclonedxutil.Canonicalize(context.Background(), bom)

		Expect(*bom.Components).To(HaveLen(1))
		Expect(recordedOccurrences(&(*bom.Components)[0])).To(Equal([]Occurrence{}),
			"a copy of the component that says nothing must not undo what werf looked for")
	})

	It("drops the verdict once the image does hold a file of the component", func() {
		bom := bomOf("pkg:pypi/requests@2.32.3")
		Expect(RecordOccurrences(bom, []Fileset{{
			Ecosystem:     EcosystemPython,
			Name:          "requests",
			Version:       "2.32.3",
			DeclaresFiles: true,
		}})).To(Equal(1))

		Expect(RecordOccurrences(bom, []Fileset{
			fileset(EcosystemPython, "requests", "2.32.3", map[string]string{"/usr/lib/python3/requests/__init__.py": "r"}, nil),
		})).To(Equal(1))

		data, err := cyclonedxutil.ToJSON(bom)
		Expect(err).NotTo(HaveOccurred())
		read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		Expect(err).NotTo(HaveOccurred())

		Expect(recordedOccurrences(&(*read.Components)[0])).To(HaveLen(1))
		Expect(propertyValue(&(*read.Components)[0], PropertyFiles)).To(BeEmpty(),
			"a document that lists a file of the component must not also say the image holds none")
	})

	It("records a component one of whose copies declares files", func() {
		bom := bomOf("pkg:npm/debug@4.3.4")

		recorded := RecordOccurrences(bom, []Fileset{
			{Ecosystem: EcosystemJavaScript, Name: "debug", Version: "4.3.4"},
			fileset(EcosystemJavaScript, "debug", "4.3.4", map[string]string{"/app/node_modules/debug/index.js": "d"}, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(HaveLen(1))
	})

	It("leaves a component of another version alone", func() {
		bom := bomOf("pkg:generic/zlib@1.3.1")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.2.13", map[string]string{"/usr/lib/libz.so.1.2.13": "old"}, nil),
		})

		Expect(recorded).To(BeZero())
		Expect(occurrencesOf(bom, 0)).To(BeNil())
	})

	It("leaves a component of another ecosystem alone, however alike it is named", func() {
		bom := bomOf("pkg:pypi/debug@4.3.4")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemJavaScript, "debug", "4.3.4", map[string]string{"/app/node_modules/debug/index.js": "d"}, nil),
		})

		Expect(recorded).To(BeZero())
		Expect(occurrencesOf(bom, 0)).To(BeNil())
	})

	It("matches a PyPI component whose purl keeps a separator the install folds", func() {
		bom := bomOf("pkg:pypi/ruamel.yaml@0.18.6")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemPython, "ruamel-yaml", "0.18.6", map[string]string{"/usr/lib/python3/ruamel/yaml/__init__.py": "y"}, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(HaveLen(1))
	})

	It("matches an npm component whose package.json spells the name in mixed case", func() {
		bom := bomOf("pkg:npm/JSONStream@1.3.5")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemJavaScript, "JSONStream", "1.3.5", map[string]string{"/app/node_modules/JSONStream/index.js": "j"}, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(HaveLen(1))
	})

	It("matches a scoped npm component to the package tree it was installed into", func() {
		bom := bomOf("pkg:npm/%40babel/core@7.24.0")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemJavaScript, "@babel/core", "7.24.0", map[string]string{"/app/node_modules/@babel/core/index.js": "b"}, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(HaveLen(1))
	})

	It("gives a component installed more than once the files of every copy", func() {
		bom := bomOf("pkg:npm/debug@4.3.4")

		RecordOccurrences(bom, []Fileset{
			fileset(EcosystemJavaScript, "debug", "4.3.4", map[string]string{"/app/node_modules/debug/index.js": "d"}, nil),
			fileset(EcosystemJavaScript, "debug", "4.3.4", map[string]string{"/app/node_modules/ms/node_modules/debug/index.js": "d"}, nil),
		})

		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/app/node_modules/debug/index.js", AdditionalContext: digestOf("d")},
			{Location: "/app/node_modules/ms/node_modules/debug/index.js", AdditionalContext: digestOf("d")},
		}))
	})

	It("says the files were looked for when a fileset names a component but the image kept none", func() {
		bom := bomOf("pkg:generic/zlib@1.3.1")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1", nil, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{}))
	})

	It("keeps the occurrences werf recorded before over a fileset the image kept no file of, but replaces a scanner's", func() {
		bom := bomOf("pkg:generic/zlib@1.3.1")
		(*bom.Components)[0].Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: "/var/lib/dpkg/status"},
		}}

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1", nil, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{}),
			"where a scanner saw the package says nothing of its files, so there is nothing worth keeping over the image's own answer")
	})

	It("leaves a component no fileset names unmarked, so nothing is known of its files", func() {
		bom := bomOf("pkg:deb/debian/libc6@2.36", "pkg:golang/gopkg.in/yaml.v3@3.0.1")

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "libc6", "2.36", map[string]string{"/lib/libc.so.6": "c"}, nil),
		})

		Expect(recorded).To(BeZero())
		Expect(occurrencesOf(bom, 0)).To(BeNil())
		Expect(occurrencesOf(bom, 1)).To(BeNil())
	})

	It("records a component nested under another", func() {
		nested := []cdx.Component{componentOf("pkg:generic/zlib@1.3.1")}
		outer := componentOf("pkg:generic/git@2.50.1")
		outer.Components = &nested
		bom := &cdx.BOM{Components: &[]cdx.Component{outer}}

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1", map[string]string{"/usr/lib/libz.so.1.3.1": "z"}, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(lo.FromPtr((*(*bom.Components)[0].Components)[0].Evidence.Occurrences)).To(HaveLen(1))
	})

	It("records a component listed under the image's own component", func() {
		nested := []cdx.Component{componentOf("pkg:generic/zlib@1.3.1")}
		bom := &cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
			Type:       cdx.ComponentTypeContainer,
			Components: &nested,
		}}}

		recorded := RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1", map[string]string{"/usr/lib/libz.so.1.3.1": "z"}, nil),
		})

		Expect(recorded).To(Equal(1))
		Expect(lo.FromPtr(nested[0].Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/libz.so.1.3.1", AdditionalContext: digestOf("z")},
		}))
	})

	It("replaces the occurrences a scanner guessed with the files the image holds", func() {
		bom := bomOf("pkg:pypi/requests@2.32.3")
		(*bom.Components)[0].Evidence = &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/usr/lib/python3/requests-2.32.3.dist-info/RECORD"}},
		}

		RecordOccurrences(bom, []Fileset{
			fileset(EcosystemPython, "requests", "2.32.3", map[string]string{"/usr/lib/python3/requests/__init__.py": "r"}, nil),
		})

		Expect(occurrencesOf(bom, 0)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("r")},
		}))
	})

	It("keeps the evidence a component already carries of another kind", func() {
		bom := bomOf("pkg:generic/zlib@1.3.1")
		(*bom.Components)[0].Evidence = &cdx.Evidence{
			Identity: &[]cdx.EvidenceIdentity{{Field: cdx.EvidenceIdentityFieldTypeCPE}},
		}

		RecordOccurrences(bom, []Fileset{
			fileset(EcosystemOSPM, "zlib", "1.3.1", map[string]string{"/usr/lib/libz.so.1.3.1": "z"}, nil),
		})

		Expect(lo.FromPtr((*bom.Components)[0].Evidence.Identity)).To(HaveLen(1))
		Expect(occurrencesOf(bom, 0)).To(HaveLen(1))
	})

	It("does nothing to a BOM when the image yielded no filesets", func() {
		bom := bomOf("pkg:generic/zlib@1.3.1")

		Expect(RecordOccurrences(bom, nil)).To(BeZero())
		Expect(occurrencesOf(bom, 0)).To(BeNil())
	})
})

var _ = Describe("HasFileBackedComponents", func() {
	bomOf := func(purls ...string) *cdx.BOM {
		components := make([]cdx.Component, 0, len(purls))
		for _, purl := range purls {
			components = append(components, cdx.Component{BOMRef: purl, Name: purl, PackageURL: purl})
		}

		return &cdx.BOM{Components: &components}
	}

	It("finds a component of each ecosystem that records file lists", func() {
		Expect(HasFileBackedComponents(bomOf("pkg:generic/zlib@1.3.1"))).To(BeTrue())
		Expect(HasFileBackedComponents(bomOf("pkg:pypi/requests@2.32.3"))).To(BeTrue())
		Expect(HasFileBackedComponents(bomOf("pkg:npm/debug@4.3.4"))).To(BeTrue())
		Expect(HasFileBackedComponents(bomOf("pkg:luarocks/luasocket@3.1.0-1"))).To(BeTrue())
	})

	It("finds nothing in a BOM whose components no ecosystem here records", func() {
		Expect(HasFileBackedComponents(bomOf(
			"pkg:golang/gopkg.in/yaml.v3@3.0.1",
			"pkg:deb/debian/libc6@2.36",
			"pkg:cargo/serde@1.0.0",
		))).To(BeFalse())
	})

	It("finds a component nested under another", func() {
		nested := []cdx.Component{{BOMRef: "z", PackageURL: "pkg:generic/zlib@1.3.1"}}
		outer := cdx.Component{BOMRef: "g", PackageURL: "pkg:golang/x@1", Components: &nested}

		Expect(HasFileBackedComponents(&cdx.BOM{Components: &[]cdx.Component{outer}})).To(BeTrue())
	})

	It("finds nothing in an empty BOM", func() {
		Expect(HasFileBackedComponents(&cdx.BOM{})).To(BeFalse())
	})
})
