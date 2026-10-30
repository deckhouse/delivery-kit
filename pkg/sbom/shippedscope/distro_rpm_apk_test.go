package shippedscope

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The rpm and apk fixtures under testdata/distrodb are databases the real tools wrote:
// ubi9-minimal (rpm 4.16, SQLite), ubi8-minimal (rpm 4.14, Berkeley DB) and ALT p10
// (rpm 4.13, Berkeley DB), each cut down to a few packages with rpm -e --justdb and
// rpm --rebuilddb, and alpine 3.20's installed database. Beside each, what the tool itself
// reports: rpm -qa NAME, EPOCHNUM, VERSION-RELEASE and ARCH and every FILENAMES, apk info
// -v and apk info -L.

func distroFixture(name string) []byte {
	GinkgoHelper()
	body, err := os.ReadFile(filepath.Join("testdata", "distrodb", name))
	Expect(err).NotTo(HaveOccurred())
	if !strings.HasSuffix(name, ".gz") {
		return body
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	Expect(err).NotTo(HaveOccurred())
	body, err = io.ReadAll(reader)
	Expect(err).NotTo(HaveOccurred())

	return body
}

func distroFixtureLines(name string) []string {
	GinkgoHelper()

	return strings.Split(strings.TrimSpace(string(distroFixture(name))), "\n")
}

func rpmFixturePackages(name string) []rpmPackage {
	GinkgoHelper()
	manifests := map[string][]byte{}
	switch name {
	case "ubi9":
		manifests["/var/lib/rpm/rpmdb.sqlite"] = distroFixture("ubi9-rpmdb.sqlite.gz")
	default:
		manifests["/var/lib/rpm/Packages"] = distroFixture(name + "-Packages.gz")
	}
	packages, err := rpmDatabasePackages([]string{"/var/lib/rpm"}, manifests)
	Expect(err).NotTo(HaveOccurred())

	return packages
}

var _ = Describe("The rpm and apk databases an image carries", func() {
	DescribeTable("reads every package rpm records, with every path, as rpm reports them",
		func(name string) {
			var packages, files []string
			for _, pkg := range rpmFixturePackages(name) {
				arch := pkg.Arch
				if arch == "" {
					arch = "(none)"
				}
				packages = append(packages, fmt.Sprintf("%s\t%d\t%s-%s\t%s", pkg.Name, pkg.Epoch, pkg.Version, pkg.Release, arch))
				for _, file := range pkg.Files {
					files = append(files, pkg.Name+"\t"+file)
				}
			}
			slices.Sort(packages)
			slices.Sort(files)

			Expect(packages).To(Equal(distroFixtureLines(name + ".packages")))
			Expect(files).To(Equal(distroFixtureLines(name + ".files.gz")))
		},
		Entry("SQLite, rpm 4.16", "ubi9"),
		Entry("Berkeley DB, rpm 4.14", "ubi8"),
		Entry("Berkeley DB, rpm 4.13 on ALT", "alt"),
	)

	It("reads every package apk records, with every path, as apk reports them", func() {
		pkgs, err := parseAPKInstalled(distroFixture("alpine-installed.gz"))
		Expect(err).NotTo(HaveOccurred())

		var packages, files []string
		for _, pkg := range pkgs {
			Expect(pkg.Arch).To(Equal("x86_64"))
			packages = append(packages, pkg.Name+"-"+pkg.Version)
			for _, file := range pkg.Files {
				files = append(files, pkg.Name+"\t"+file)
			}
		}
		slices.Sort(packages)
		slices.Sort(files)

		Expect(packages).To(Equal(distroFixtureLines("alpine.packages")))
		Expect(files).To(Equal(distroFixtureLines("alpine.files.gz")))
	})

	// A database read in part would leave the packages it did not reach looking absent,
	// so every damage to one must come back as an error and never as a shorter list.
	DescribeTable("refuses a database cut short anywhere, without a panic",
		func(name string) {
			var body []byte
			read := func(b []byte) (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
						Fail(err.Error())
					}
				}()
				var blobs [][]byte
				if name == "ubi9-rpmdb.sqlite.gz" {
					blobs, err = sqliteTableBlobs(b, "Packages", 1)
				} else {
					var values map[uint32][]byte
					values, err = bdbHashValues(b)
					for _, value := range values {
						blobs = append(blobs, value)
					}
				}
				for _, blob := range blobs {
					if err == nil {
						_, err = parseRPMHeader(blob)
					}
				}

				return err
			}
			body = distroFixture(name)
			Expect(read(body)).To(Succeed())
			for cut := 1; cut < len(body); cut += 4093 {
				Expect(read(body[:cut])).NotTo(Succeed(), "cut at %d", cut)
			}
			// A damaged byte may land where nothing checks it; it must never crash the build.
			for at := 0; at < len(body); at += 211 {
				damaged := slices.Clone(body)
				damaged[at] ^= 0xa5
				_ = read(damaged)
			}
		},
		Entry("SQLite", "ubi9-rpmdb.sqlite.gz"),
		Entry("Berkeley DB", "ubi8-Packages.gz"),
	)

	It("refuses an rpm header that does not hold together", func() {
		blob := rpmFixturePackagesBlob()
		_, err := parseRPMHeader(blob)
		Expect(err).NotTo(HaveOccurred())

		duplicated := slices.Clone(blob)
		// Point the second index entry at the name tag: the header now states it twice.
		binary.BigEndian.PutUint32(duplicated[8+16:], rpmTagName)
		binary.BigEndian.PutUint32(duplicated[8+16+4:], rpmTypeString)
		binary.BigEndian.PutUint32(duplicated[8:], rpmTagName)
		binary.BigEndian.PutUint32(duplicated[8+4:], rpmTypeString)
		_, err = parseRPMHeader(duplicated)
		Expect(err).To(MatchError(ContainSubstring("twice")))

		outside := slices.Clone(blob)
		binary.BigEndian.PutUint32(outside[4:], 0)
		_, err = parseRPMHeader(outside)
		Expect(err).To(HaveOccurred())
	})

	It("counts the directories apk made as declared, as dpkg and rpm do", func(ctx SpecContext) {
		database := databaseOf(ctx, []tarEntry{regularFile("lib/apk/db/installed", "P:dirs-only\nV:1.0-r0\nA:x86_64\nF:etc/dirs-only\n\n")})

		Expect(database.Packages[ManagerPackageKey(apkPurlType, "dirs-only", "1.0-r0", "x86_64")].DeclaresFiles).To(BeTrue())
	})

	It("refuses an apk database it cannot read whole", func() {
		_, err := parseAPKInstalled([]byte("P:busybox\nV:1.0\nR:busybox\n"))
		Expect(err).To(MatchError(ContainSubstring("before its directory")))
		_, err = parseAPKInstalled([]byte("P:busybox\nA:x86_64\n\n"))
		Expect(err).To(MatchError(ContainSubstring("no package or version")))
	})
})

// rpmFixturePackagesBlob is one real header blob, for tests that damage it.
func rpmFixturePackagesBlob() []byte {
	GinkgoHelper()
	blobs, err := sqliteTableBlobs(distroFixture("ubi9-rpmdb.sqlite.gz"), "Packages", 1)
	Expect(err).NotTo(HaveOccurred())

	return blobs[0]
}

const (
	ubi9GMP     = "pkg:rpm/redhat/gmp@6.2.0-13.el9?arch=x86_64&epoch=1&distro=rhel-9.8"
	ubi9GMPFile = "usr/lib64/libgmp.so.10.4.0"
)

func ubi9Layout(extra ...tarEntry) []tarEntry {
	return append([]tarEntry{
		regularFile("var/lib/rpm/rpmdb.sqlite", string(distroFixture("ubi9-rpmdb.sqlite.gz"))),
		regularFile(ubi9GMPFile, "gmp"),
		symlink("usr/lib64/libgmp.so.10", "libgmp.so.10.4.0"),
	}, extra...)
}

func alpineLayout(extra ...tarEntry) []tarEntry {
	return append([]tarEntry{
		regularFile("lib/apk/db/installed", string(distroFixture("alpine-installed.gz"))),
		regularFile("bin/busybox", "busybox"),
	}, extra...)
}

var _ = Describe("Placing inherited rpm and apk packages", func() {
	supplied := func(purl string) *cdx.BOM {
		return &cdx.BOM{Components: &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, BOMRef: purl, Name: "pkg", Version: "1", PackageURL: purl}}}
	}
	place := func(ctx context.Context, purl string, entries []tarEntry) (*cdx.Component, []int) {
		GinkgoHelper()
		bom := supplied(purl)
		placed, absent := PlaceInheritedPackages(ctx, bom, databaseOf(ctx, entries))

		return &(*bom.Components)[0], []int{placed, absent}
	}

	It("places an rpm package the database records, at the files the image holds", func(ctx SpecContext) {
		comp, counts := place(ctx, ubi9GMP, ubi9Layout())

		Expect(counts).To(Equal([]int{1, 0}))
		Expect(recordedOccurrences(comp)).To(HaveLen(2), "the library and its symlink; the other recorded paths are not in this image")
	})

	It("places an apk package the database records", func(ctx SpecContext) {
		comp, counts := place(ctx, "pkg:apk/alpine/busybox@1.36.1-r31?arch=x86_64&distro=3.20.6", alpineLayout())

		Expect(counts).To(Equal([]int{1, 0}))
		Expect(recordedOccurrences(comp)).To(HaveLen(1))
	})

	DescribeTable("reads the epoch an rpm purl spells in front of the version",
		func(ctx SpecContext, purl string) {
			_, counts := place(ctx, purl, ubi9Layout())

			Expect(counts).To(Equal([]int{1, 0}))
		},
		Entry("alone", "pkg:rpm/redhat/gmp@1:6.2.0-13.el9?arch=x86_64"),
		Entry("and again as a qualifier", "pkg:rpm/redhat/gmp@1:6.2.0-13.el9?arch=x86_64&epoch=1"),
	)

	// rpm keys a build without an epoch and one with epoch 0 alike.
	DescribeTable("takes an explicit zero epoch for none",
		func(ctx SpecContext, purl string) {
			_, counts := place(ctx, purl, []tarEntry{
				regularFile("var/lib/rpm/Packages", string(distroFixture("alt-Packages.gz"))),
				regularFile("lib64/libpcre.so.3.15.13", "pcre"),
			})

			Expect(counts).To(Equal([]int{1, 0}))
		},
		Entry("in front of the version", "pkg:rpm/altlinux/libpcre3@0:8.45-alt1?arch=x86_64"),
		Entry("in front of the version and as a qualifier", "pkg:rpm/altlinux/libpcre3@0:8.45-alt1?arch=x86_64&epoch=0"),
		Entry("as a qualifier", "pkg:rpm/altlinux/libpcre3@8.45-alt1?arch=x86_64&epoch=0"),
	)

	DescribeTable("marks a package its own database does not record as not shipped",
		func(ctx SpecContext, purl string, entries func(...tarEntry) []tarEntry) {
			comp, counts := place(ctx, purl, entries())

			Expect(counts).To(Equal([]int{0, 1}))
			Expect(propertyValue(comp, PropertyShipped)).To(Equal(PropertyShippedFalse))
		},
		Entry("rpm at another version", "pkg:rpm/redhat/gmp@6.2.0-14.el9?arch=x86_64&epoch=1", ubi9Layout),
		Entry("rpm under another epoch", "pkg:rpm/redhat/gmp@6.2.0-13.el9?arch=x86_64&epoch=2", ubi9Layout),
		Entry("rpm stating epoch 0 for a build that has one", "pkg:rpm/redhat/gmp@6.2.0-13.el9?arch=x86_64&epoch=0", ubi9Layout),
		Entry("rpm for another architecture", "pkg:rpm/redhat/gmp@6.2.0-13.el9?arch=aarch64&epoch=1", ubi9Layout),
		Entry("rpm it has never heard of", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64", ubi9Layout),
		Entry("apk at another version", "pkg:apk/alpine/busybox@1.36.1-r30?arch=x86_64", alpineLayout),
		Entry("apk it has never heard of", "pkg:apk/alpine/bash@5.2.26-r0?arch=x86_64", alpineLayout),
	)

	DescribeTable("concludes nothing it cannot settle",
		func(ctx SpecContext, purl string, entries []tarEntry) {
			comp, counts := place(ctx, purl, entries)

			Expect(counts).To(Equal([]int{0, 0}))
			Expect(propertyValue(comp, PropertyShipped)).To(BeEmpty())
			Expect(recordedOccurrences(comp)).To(BeNil())
		},
		// The build carries epoch 1; a purl without one may mean it or a build without.
		Entry("an rpm purl naming no epoch for a build that has one", "pkg:rpm/redhat/gmp@6.2.0-13.el9?arch=x86_64", ubi9Layout()),
		Entry("an rpm package recorded with no files", "pkg:rpm/redhat/gpg-pubkey@fd431d51-4ae0493b", ubi9Layout()),
		Entry("an rpm package in an image whose only database is dpkg's", ubi9GMP, debianLayout()),
		Entry("a deb package in an image whose only database is rpm's", "pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64", ubi9Layout()),
		Entry("an apk package in an image whose only database is rpm's", "pkg:apk/alpine/busybox@1.36.1-r31?arch=x86_64", ubi9Layout()),
		Entry("an rpm package when the SQLite database has an unmerged log", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
			ubi9Layout(regularFile("var/lib/rpm/rpmdb.sqlite-wal", "frames"))),
		Entry("an rpm package when the SQLite database has an unfinished transaction", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
			ubi9Layout(regularFile("var/lib/rpm/rpmdb.sqlite-journal", "journal"))),
		Entry("an rpm package when rpm keeps an ndb database", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
			[]tarEntry{regularFile("usr/lib/sysimage/rpm/Packages.db", "ndb")}),
		Entry("an rpm package when there are databases in both places", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
			ubi9Layout(regularFile("usr/lib/sysimage/rpm/rpmdb.sqlite", string(distroFixture("ubi9-rpmdb.sqlite.gz"))))),
		Entry("an rpm package when one directory keeps two forms", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
			ubi9Layout(regularFile("var/lib/rpm/Packages", string(distroFixture("ubi8-Packages.gz"))))),
		Entry("an rpm package when the database is damaged", "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
			[]tarEntry{regularFile("var/lib/rpm/Packages", string(distroFixture("ubi8-Packages.gz")[:8192]))}),
		Entry("an apk package when the database is damaged", "pkg:apk/alpine/bash@5.2.26-r0?arch=x86_64",
			[]tarEntry{regularFile("lib/apk/db/installed", "P:bash\nR:bash\n")}),
		Entry("an apk package when there are databases in both places", "pkg:apk/alpine/bash@5.2.26-r0?arch=x86_64",
			alpineLayout(regularFile("usr/lib/apk/db/installed", "P:bash\nV:5.2.26-r0\nA:x86_64\n"))),
	)

	// An image may carry more than one manager's database; each answers for its own
	// packages only.
	DescribeTable("judges a package by its own manager's database alone, with dpkg's beside it",
		func(ctx SpecContext, purl string) {
			comp, counts := place(ctx, purl, ubi9Layout(debianLayout()...))

			Expect(counts).To(Equal([]int{0, 1}))
			Expect(propertyValue(comp, PropertyShipped)).To(Equal(PropertyShippedFalse))
		},
		Entry("an rpm purl naming exactly a deb the image has", "pkg:rpm/redhat/libc6@2.36-9+deb12u7?arch=amd64"),
		Entry("an rpm purl naming, with no architecture, a deb the image has", "pkg:rpm/redhat/libc6@2.0"),
	)

	It("reads the database where a distribution keeps it behind a symlink", func(ctx SpecContext) {
		_, counts := place(ctx, ubi9GMP, []tarEntry{
			symlink("var/lib/rpm", "../../usr/lib/sysimage/rpm"),
			regularFile("usr/lib/sysimage/rpm/rpmdb.sqlite", string(distroFixture("ubi9-rpmdb.sqlite.gz"))),
			regularFile(ubi9GMPFile, "gmp"),
		})

		Expect(counts).To(Equal([]int{1, 0}))
	})

	// One header that does not read leaves its package unknown, and every other package
	// would then read as the whole of what is installed.
	It("reads nothing of an rpm database with one header it cannot read", func(ctx SpecContext) {
		db := distroFixture("ubi9-rpmdb.sqlite.gz")
		blob := rpmFixturePackagesBlob()
		// Freed pages may still hold an old copy; damage every one.
		Expect(bytes.Count(db, blob[:64])).To(BeNumerically(">", 0))
		for at := bytes.Index(db, blob[:64]); at >= 0; at = bytes.Index(db, blob[:64]) {
			binary.BigEndian.PutUint32(db[at:], 0)
		}

		comp, counts := place(ctx, "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64", []tarEntry{regularFile("var/lib/rpm/rpmdb.sqlite", string(db))})

		Expect(counts).To(Equal([]int{0, 0}))
		Expect(propertyValue(comp, PropertyShipped)).To(BeEmpty())
	})

	It("says why it did not read a database", func(ctx SpecContext) {
		database := databaseOf(ctx, ubi9Layout(regularFile("var/lib/rpm/rpmdb.sqlite-wal", "frames")))

		Expect(database.Managers).NotTo(HaveKey(rpmPurlType))
		Expect(database.Unread).To(HaveKeyWithValue(rpmPurlType, ContainSubstring("write-ahead log")))
	})
})
