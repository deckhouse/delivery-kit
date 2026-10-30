package shippedscope

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

// debianLayout is the usual dpkg database: one status file, and one file list per package
// under info/.
func debianLayout(extra ...tarEntry) []tarEntry {
	entries := []tarEntry{
		regularFile("var/lib/dpkg/status", `Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.36-9+deb12u7
Description: GNU C Library
 This is a continuation line, and carries no field of its own.
 Package: not-a-package

Package: zlib1g
Status: install ok installed
Architecture: amd64
Version: 1:1.2.13.dfsg-1

Package: removed-but-not-purged
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0
`),
		regularFile("var/lib/dpkg/info/libc6.list", "/.\n/lib\n/lib/x86_64-linux-gnu/libc.so.6\n/usr/share/doc/libc6/copyright\n"),
		regularFile("var/lib/dpkg/info/zlib1g.list", "/lib/x86_64-linux-gnu/libz.so.1\n"),
		regularFile("lib/x86_64-linux-gnu/libc.so.6", "libc"),
		regularFile("lib/x86_64-linux-gnu/libz.so.1", "libz"),
		regularFile("usr/share/doc/libc6/copyright", "copyright"),
	}

	return append(entries, extra...)
}

// distrolessLayout is what an image with no dpkg binary keeps: a stanza per package under
// status.d, and the md5sums list beside it.
func distrolessLayout() []tarEntry {
	return []tarEntry{
		regularFile("var/lib/dpkg/status.d/base-files", "Package: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 12.4+deb12u5\n"),
		regularFile("var/lib/dpkg/status.d/base-files.md5sums", "d41d8cd98f00b204e9800998ecf8427e  etc/debian_version\n5d41402abc4b2a76b9719d911017c592  usr/share/base-files/motd\n"),
		regularFile("etc/debian_version", "12.4"),
		regularFile("usr/share/base-files/motd", "hello"),
	}
}

func databaseOf(ctx context.Context, entries []tarEntry) *DistroDatabase {
	GinkgoHelper()
	img, err := imageOf(entries)
	Expect(err).NotTo(HaveOccurred())
	database, err := DistroPackages(ctx, img)
	Expect(err).NotTo(HaveOccurred())

	return database
}

func packagesOf(ctx context.Context, entries []tarEntry) (map[string]DistroPackage, *FileIndex) {
	GinkgoHelper()
	database := databaseOf(ctx, entries)

	return database.Packages, database.Index
}

var _ = Describe("The package database an image carries", func() {
	It("reads the packages dpkg says are installed, with the files it recorded", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, debianLayout())

		libc := packages[DistroPackageKey("libc6", "2.36-9+deb12u7", "amd64")]
		Expect(libc.DeclaresFiles).To(BeTrue())
		Expect(InheritedPackagePaths(libc)).To(Equal([]string{
			"/lib/x86_64-linux-gnu/libc.so.6", "/usr/share/doc/libc6/copyright",
		}), "the directories dpkg made are not files of the package, and the root is not one either")
		Expect(libc.Files["/lib/x86_64-linux-gnu/libc.so.6"].Digest).To(HavePrefix("sha256:"), "the digest is of what the image holds")

		Expect(packages).To(HaveKey(DistroPackageKey("zlib1g", "1:1.2.13.dfsg-1", "amd64")))
	})

	// A stanza is not a package: dpkg keeps one for a package whose files were removed
	// and whose configuration was not.
	It("reads no package the database says is not installed", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, debianLayout())

		Expect(packages).NotTo(HaveKey(DistroPackageKey("removed-but-not-purged", "1.0", "amd64")))
	})

	// A field continued over several lines carries no field of its own, however much
	// the text of it looks like one.
	It("reads a continuation line as part of the field above it", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, debianLayout())

		names := make([]string, 0, len(packages))
		for _, entry := range packages {
			names = append(names, entry.Name)
		}
		Expect(names).To(ConsistOf("libc6", "zlib1g"))
	})

	// dpkg lists the directories it made alongside the files it put in them, and spells
	// the root "/.". A package that lists nothing else declares no files of its own,
	// which is not the same as one whose files are gone.
	It("reads a list of nothing but directories as declaring no files", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 12.4\n"),
			regularFile("var/lib/dpkg/info/base-files.list", "/.\n"),
		})

		Expect(packages[DistroPackageKey("base-files", "12.4", "amd64")].DeclaresFiles).To(BeFalse())
	})

	It("reads the per-package form a distroless image keeps", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, distrolessLayout())

		entry := packages[DistroPackageKey("base-files", "12.4+deb12u5", "amd64")]
		Expect(entry.DeclaresFiles).To(BeTrue())
		Expect(InheritedPackagePaths(entry)).To(Equal([]string{"/etc/debian_version", "/usr/share/base-files/motd"}),
			"an md5sums list spells its paths relative to the root")
	})

	It("reads the file list of a package of a foreign architecture", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: libc6\nStatus: install ok installed\nArchitecture: i386\nVersion: 2.36\n"),
			regularFile("var/lib/dpkg/info/libc6:i386.list", "/lib/i386-linux-gnu/libc.so.6\n"),
			regularFile("lib/i386-linux-gnu/libc.so.6", "libc"),
		})

		Expect(InheritedPackagePaths(packages[DistroPackageKey("libc6", "2.36", "i386")])).
			To(Equal([]string{"/lib/i386-linux-gnu/libc.so.6"}))
	})

	// The fileset describes what shipped, not what was installed.
	It("leaves out a file the database lists and the image no longer holds", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.2\n"),
			regularFile("var/lib/dpkg/info/zlib1g.list", "/lib/libz.so.1\n/usr/share/doc/zlib1g/changelog\n"),
			regularFile("lib/libz.so.1", "libz"),
		})

		Expect(InheritedPackagePaths(packages[DistroPackageKey("zlib1g", "1.2", "amd64")])).To(Equal([]string{"/lib/libz.so.1"}))
	})

	It("names a file where the image has it when a directory above it is a symlink", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n"),
			regularFile("var/lib/dpkg/info/libfoo.list", "/lib64/libfoo.so\n"),
			symlink("lib64", "/usr/lib"),
			regularFile("usr/lib/libfoo.so", "foo"),
		})

		Expect(InheritedPackagePaths(packages[DistroPackageKey("libfoo", "1.0", "amd64")])).To(Equal([]string{"/usr/lib/libfoo.so"}))
	})

	// An entry with no list at all is installed and placed nowhere, which is not the
	// same as one whose listed files are gone.
	It("tells a package with no file list from one whose files are gone", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: metapackage\nStatus: install ok installed\nArchitecture: all\nVersion: 1.0\n\nPackage: emptied\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.0\n"),
			regularFile("var/lib/dpkg/info/emptied.list", "/opt/gone\n"),
		})

		Expect(packages[DistroPackageKey("metapackage", "1.0", "all")].DeclaresFiles).To(BeFalse())
		emptied := packages[DistroPackageKey("emptied", "2.0", "amd64")]
		Expect(emptied.DeclaresFiles).To(BeTrue())
		Expect(emptied.Files).To(BeEmpty())
	})

	It("reads no database out of an image that carries none", func(ctx SpecContext) {
		database := databaseOf(ctx, []tarEntry{regularFile("usr/bin/app", "app")})

		Expect(database.Present).To(BeFalse())
		Expect(database.Packages).To(BeEmpty())
		Expect(database.Index.Files).To(HaveKey("/usr/bin/app"))
	})

	It("finds the database of an image that carries one, in either form", func(ctx SpecContext) {
		Expect(databaseOf(ctx, debianLayout()).Present).To(BeTrue())
		Expect(databaseOf(ctx, distrolessLayout()).Present).To(BeTrue())
	})

	// Only the stanzas are the database's statement of what is installed; the file list
	// beside one in the per-package form is not a stanza, whatever it parses as.
	It("reads no package out of the md5sums list beside a stanza", func(ctx SpecContext) {
		packages, _ := packagesOf(ctx, distrolessLayout())

		Expect(packages).To(HaveLen(1))
	})

	// dpkg leaves the files of a package on disk in every state but the two that mean it
	// was never unpacked or has been removed.
	DescribeTable("reads a package whose files are on disk however far its configuration got",
		func(ctx SpecContext, status string, installed bool) {
			packages, _ := packagesOf(ctx, []tarEntry{
				regularFile("var/lib/dpkg/status", "Package: libfoo\nStatus: "+status+"\nArchitecture: amd64\nVersion: 1.0\n"),
			})

			Expect(packages).To(HaveLen(lo.Ternary(installed, 1, 0)), status)
		},
		Entry("installed", "install ok installed", true),
		Entry("unpacked", "install ok unpacked", true),
		Entry("half-configured", "install ok half-configured", true),
		Entry("half-installed", "install reinstreq half-installed", true),
		Entry("awaiting a trigger", "install ok triggers-awaited", true),
		Entry("pending a trigger", "install ok triggers-pending", true),
		Entry("removed but not purged", "deinstall ok config-files", false),
		Entry("never installed", "purge ok not-installed", false),
	)
})

var _ = Describe("Placing the packages an image inherited from its supplier", func() {
	supplier := func(purl string) *cdx.BOM {
		bom := &cdx.BOM{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, BOMRef: purl, Name: "libc6", Version: "2.36-9+deb12u7", PackageURL: purl,
		}}}

		return bom
	}

	place := func(ctx context.Context, bom *cdx.BOM, entries []tarEntry) (int, int) {
		GinkgoHelper()

		return PlaceInheritedPackages(ctx, bom, databaseOf(ctx, entries))
	}

	// An image carrying no database of its own says nothing about the packages of its
	// base. Reading its silence as their absence would be a statement nobody made.
	It("concludes nothing where the image carries no database at all", func(ctx SpecContext) {
		bom := supplier("pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64")

		placed, absent := place(ctx, bom, []tarEntry{regularFile("usr/bin/app", "app")})

		Expect([]int{placed, absent}).To(Equal([]int{0, 0}))
		Expect(propertyValue(&(*bom.Components)[0], PropertyShipped)).To(BeEmpty())
		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("places a package the database records, at the files it holds", func(ctx SpecContext) {
		bom := supplier("pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12")

		placed, absent := place(ctx, bom, debianLayout())

		Expect([]int{placed, absent}).To(Equal([]int{1, 0}))
		Expect(recordedOccurrences(&(*bom.Components)[0])).To(HaveLen(2))
		Expect(propertyValue(&(*bom.Components)[0], PropertyShipped)).To(BeEmpty())
	})

	// The database is the authority on what is installed: the same name at another
	// version, or for another architecture, is another package than the one shipped.
	DescribeTable("marks a package the database does not record as not shipped",
		func(ctx SpecContext, purl string) {
			bom := supplier(purl)

			placed, absent := place(ctx, bom, debianLayout())

			Expect([]int{placed, absent}).To(Equal([]int{0, 1}))
			Expect(propertyValue(&(*bom.Components)[0], PropertyShipped)).To(Equal(PropertyShippedFalse))
			Expect(recordedOccurrences(&(*bom.Components)[0])).To(BeNil())
		},
		Entry("at another version", "pkg:deb/debian/libc6@2.31-13?arch=amd64&distro=debian-11"),
		Entry("for another architecture", "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=arm64&distro=debian-12"),
		Entry("under a name it has never heard of", "pkg:deb/debian/libc-bin@2.36-9+deb12u7?arch=amd64&distro=debian-12"),
		Entry("under a name it has never heard of, stating no architecture", "pkg:deb/debian/libc-bin@2.36-9+deb12u7"),
	)

	It("leaves a package the database records with no file list placed nowhere", func(ctx SpecContext) {
		bom := &cdx.BOM{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, BOMRef: "meta", Name: "metapackage", Version: "1.0",
			PackageURL: "pkg:deb/debian/metapackage@1.0?arch=all",
		}}}

		placed, absent := place(ctx, bom, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: metapackage\nStatus: install ok installed\nArchitecture: all\nVersion: 1.0\n"),
		})

		Expect([]int{placed, absent}).To(Equal([]int{0, 0}))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
		Expect(propertyValue(&(*bom.Components)[0], PropertyShipped)).To(BeEmpty())
	})

	// rpm keeps its database in sqlite or Berkeley DB, which nothing here opens, and
	// apk's is not read either. Their components stay exactly as they arrived: a package
	// of another manager is not absent from the image because dpkg never heard of it,
	// and saying so would be a statement about a database nobody opened.
	DescribeTable("says nothing of a package whose database this does not read",
		func(ctx SpecContext, purl string) {
			bom := supplier(purl)

			placed, absent := place(ctx, bom, debianLayout())

			Expect([]int{placed, absent}).To(Equal([]int{0, 0}))
			Expect(propertyValue(&(*bom.Components)[0], PropertyShipped)).To(BeEmpty())
			Expect((*bom.Components)[0].Evidence).To(BeNil())
		},
		Entry("an rpm package", "pkg:rpm/fedora/glibc@2.38-16.fc39?arch=x86_64"),
		Entry("an apk package", "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64"),
	)

	DescribeTable("leaves alone a component this pass does not own",
		func(ctx SpecContext, comp cdx.Component) {
			bom := &cdx.BOM{Components: &[]cdx.Component{comp}}

			placed, absent := place(ctx, bom, debianLayout())

			Expect([]int{placed, absent}).To(Equal([]int{0, 0}))
		},
		Entry("one of another ecosystem", cdx.Component{Name: "flask", Version: "3.0", PackageURL: "pkg:pypi/flask@3.0"}),
		Entry("one with no purl at all", cdx.Component{Name: "libc6", Version: "2.36-9+deb12u7"}),
		Entry("one the scan already placed", cdx.Component{
			Name: "libc6", Version: "2.36-9+deb12u7", PackageURL: "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64",
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/lib/x86_64-linux-gnu/libc.so.6"}}},
		}),
		Entry("one already judged not shipped", cdx.Component{
			Name: "libc6", Version: "2.36-9+deb12u7", PackageURL: "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64",
			Properties: &[]cdx.Property{{Name: PropertyShipped, Value: PropertyShippedFalse}},
		}),
		Entry("one already checked for files", cdx.Component{
			Name: "libc6", Version: "2.36-9+deb12u7", PackageURL: "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64",
			Properties: &[]cdx.Property{{Name: PropertyFiles, Value: PropertyFilesNone}},
		}),
	)

	// Matching is on name, version and architecture together. A component that leaves
	// the architecture out cannot be matched to an entry recorded under one - but it
	// cannot be called absent either, since the name is installed here.
	It("says nothing of a package that names no architecture the database records it under", func(ctx SpecContext) {
		bom := supplier("pkg:deb/debian/libc6@2.36-9+deb12u7")

		placed, absent := place(ctx, bom, debianLayout())

		Expect([]int{placed, absent}).To(Equal([]int{0, 0}))
		Expect(propertyValue(&(*bom.Components)[0], PropertyShipped)).To(BeEmpty())
		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("places a package by the architecture the database records, when the purl names it", func(ctx SpecContext) {
		bom := supplier("pkg:deb/debian/metapackage@1.0?arch=all")
		(*bom.Components)[0].Name = "metapackage"

		placed, _ := place(ctx, bom, []tarEntry{
			regularFile("var/lib/dpkg/status", "Package: metapackage\nStatus: install ok installed\nArchitecture: all\nVersion: 1.0\n"),
			regularFile("var/lib/dpkg/info/metapackage.list", "/usr/share/metapackage/marker\n"),
			regularFile("usr/share/metapackage/marker", "marker"),
		})

		Expect(placed).To(Equal(1))
		Expect(recordedOccurrences(&(*bom.Components)[0])).To(HaveLen(1))
	})
})
