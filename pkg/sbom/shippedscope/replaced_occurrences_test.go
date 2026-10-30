package shippedscope

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("DropReplacedOccurrences", func() {
	const bundle = "/etc/ssl/certs/ca-certificates.crt"

	inherited := func(occurrences ...cdx.EvidenceOccurrence) *cdx.BOM {
		comp := cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: "base-ca", Name: "ca-certificates", Version: "20210119",
			PackageURL: "pkg:deb/debian/ca-certificates@20210119?arch=all",
		}
		if occurrences != nil {
			comp.Evidence = &cdx.Evidence{Occurrences: &occurrences}
		}

		return &cdx.BOM{Components: &[]cdx.Component{comp}}
	}

	occurrenceOf := func(path, body string) cdx.EvidenceOccurrence {
		return cdx.EvidenceOccurrence{Location: path, AdditionalContext: digestOf(body)}
	}

	paths := func(bom *cdx.BOM) []string {
		located := make([]string, 0)
		for _, occurrence := range lo.FromPtr(lo.FromPtr((*bom.Components)[0].Evidence).Occurrences) {
			located = append(located, occurrence.Location)
		}

		return located
	}

	verdict := func(bom *cdx.BOM) string {
		return propertyValue(&(*bom.Components)[0], PropertyShipped)
	}

	It("drops the base's whereabouts of a file the image holds with other bytes", func(ctx SpecContext) {
		bom := inherited(occurrenceOf(bundle, "the bundle the base shipped"))

		dropped, marked := DropReplacedOccurrences(ctx, bom, indexOf(map[string]File{
			bundle: {Digest: digestOf("the bundle the package regenerated"), Size: 34},
		}))

		Expect([]int{dropped, marked}).To(Equal([]int{1, 1}))
		Expect(paths(bom)).To(BeEmpty())
		Expect(verdict(bom)).To(Equal(PropertyShippedFalse))
	})

	It("keeps a component standing at a path the image bears out, dropping the one it does not", func(ctx SpecContext) {
		bom := inherited(
			occurrenceOf(bundle, "the bundle the base shipped"),
			occurrenceOf("/usr/sbin/update-ca-certificates", "script"),
		)

		dropped, marked := DropReplacedOccurrences(ctx, bom, indexOf(map[string]File{
			bundle:                             {Digest: digestOf("the bundle the package regenerated"), Size: 34},
			"/usr/sbin/update-ca-certificates": {Digest: digestOf("script"), Size: 6},
		}))

		Expect([]int{dropped, marked}).To(Equal([]int{1, 0}))
		Expect(paths(bom)).To(ConsistOf("/usr/sbin/update-ca-certificates"))
		Expect(verdict(bom)).To(BeEmpty())
	})

	It("leaves a file the image holds as the base recorded it", func(ctx SpecContext) {
		bom := inherited(occurrenceOf(bundle, "the bundle the base shipped"))

		dropped, marked := DropReplacedOccurrences(ctx, bom, indexOf(map[string]File{
			bundle: {Digest: digestOf("the bundle the base shipped"), Size: 27},
		}))

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf(bundle))
		Expect(verdict(bom)).To(BeEmpty())
	})

	It("drops a path the image does not hold at all", func(ctx SpecContext) {
		bom := inherited(occurrenceOf(bundle, "the bundle the base shipped"))

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{1, 1}))
		Expect(verdict(bom)).To(Equal(PropertyShippedFalse))
	})

	// What a package database named, and what a scanner noted, says where a file is and
	// nothing of what is in it.
	It("holds an occurrence stating no digest to the path alone", func(ctx SpecContext) {
		bom := inherited(
			cdx.EvidenceOccurrence{Location: bundle},
			cdx.EvidenceOccurrence{Location: "/usr/share/ca-certificates/gone.crt"},
		)

		dropped, marked := DropReplacedOccurrences(ctx, bom, indexOf(map[string]File{
			bundle: {Digest: digestOf("the bundle the package regenerated"), Size: 34},
		}))

		Expect([]int{dropped, marked}).To(Equal([]int{1, 0}))
		Expect(paths(bom)).To(ConsistOf(bundle))
	})

	It("keeps a symlink the image holds, which carries no bytes of its own", func(ctx SpecContext) {
		bom := inherited(cdx.EvidenceOccurrence{Location: "/etc/ssl/cert.pem", AdditionalContext: symlinkContext})
		index := emptyIndex()
		index.Symlinks["/etc/ssl/cert.pem"] = "certs/ca-certificates.crt"

		dropped, marked := DropReplacedOccurrences(ctx, bom, index)

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf("/etc/ssl/cert.pem"))
	})

	It("leaves a component already judged not shipped as it is", func(ctx SpecContext) {
		bom := inherited(occurrenceOf(bundle, "the bundle the base shipped"))
		setProperty(&(*bom.Components)[0], PropertyShipped, PropertyShippedFalse)

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf(bundle))
	})

	// Its occurrences are provenance rather than a list of what it ships, so their
	// absence from the image settles nothing about it.
	It("leaves a component whose file evidence is declared incomplete", func(ctx SpecContext) {
		bom := inherited(occurrenceOf(bundle, "the bundle the base shipped"))
		setProperty(&(*bom.Components)[0], PropertyFiles, propertyFilesUnknown)

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf(bundle))
		Expect(verdict(bom)).To(BeEmpty())
	})

	It("concludes nothing from an index that did not read whole", func(ctx SpecContext) {
		bom := inherited(occurrenceOf(bundle, "the bundle the base shipped"))
		index := emptyIndex()
		index.Incomplete = true

		dropped, marked := DropReplacedOccurrences(ctx, bom, index)

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf(bundle))
		Expect(verdict(bom)).To(BeEmpty())
	})

	// Most bases merged /lib into /usr/lib, and the placement records a file under both
	// spellings: the one the package database names and the one the image holds it under.
	It("reads both spellings of a merged directory as the one file", func(ctx SpecContext) {
		bom := inherited(
			occurrenceOf("/lib/x86_64-linux-gnu/libfoo.so", "foo"),
			occurrenceOf("/usr/lib/x86_64-linux-gnu/libfoo.so", "foo"),
		)
		index := indexOf(map[string]File{"/usr/lib/x86_64-linux-gnu/libfoo.so": {Digest: digestOf("foo"), Size: 3}})
		index.Symlinks["/lib"] = "usr/lib"

		dropped, marked := DropReplacedOccurrences(ctx, bom, index)

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf("/lib/x86_64-linux-gnu/libfoo.so", "/usr/lib/x86_64-linux-gnu/libfoo.so"))
		Expect(verdict(bom)).To(BeEmpty())
	})

	// A document that spells the path without its root names the same file, and the same
	// bookkeeping.
	It("reads a path the document spelled without a root", func(ctx SpecContext) {
		bom := inherited(cdx.EvidenceOccurrence{Location: "var/lib/dpkg/info/ca-certificates.list"})

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf("var/lib/dpkg/info/ca-certificates.list"))
		Expect(verdict(bom)).To(BeEmpty())
	})

	// A build that strips the documentation of its base, or installs a package that
	// rewrites a database entry, has said nothing about the files its base's packages ship.
	It("judges no path of a package manager's own bookkeeping", func(ctx SpecContext) {
		bom := inherited(
			cdx.EvidenceOccurrence{Location: "/var/lib/dpkg/info/ca-certificates.list"},
			cdx.EvidenceOccurrence{Location: "/usr/share/doc/ca-certificates/copyright"},
		)

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(HaveLen(2))
		Expect(verdict(bom)).To(BeEmpty())
	})

	It("keeps such a path beside the payload it drops, and judges the component by the payload", func(ctx SpecContext) {
		bom := inherited(
			cdx.EvidenceOccurrence{Location: "/var/lib/dpkg/info/ca-certificates.list"},
			occurrenceOf(bundle, "the bundle the base shipped"),
		)

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{1, 1}))
		Expect(paths(bom)).To(ConsistOf("/var/lib/dpkg/info/ca-certificates.list"))
		Expect(verdict(bom)).To(Equal(PropertyShippedFalse))
	})

	// A package database names the directories it owns as well as the files in them.
	It("keeps a path the image holds as a directory", func(ctx SpecContext) {
		bom := inherited(cdx.EvidenceOccurrence{Location: "/usr/share/ca-certificates"})
		index := emptyIndex()
		index.Directories = map[string]struct{}{"/usr/share/ca-certificates": {}}

		dropped, marked := DropReplacedOccurrences(ctx, bom, index)

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect(paths(bom)).To(ConsistOf("/usr/share/ca-certificates"))
	})

	It("leaves a component stating nowhere it stands to the pass that owns it", func(ctx SpecContext) {
		bom := inherited()

		dropped, marked := DropReplacedOccurrences(ctx, bom, emptyIndex())

		Expect([]int{dropped, marked}).To(Equal([]int{0, 0}))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
		Expect(verdict(bom)).To(BeEmpty())
	})
})
