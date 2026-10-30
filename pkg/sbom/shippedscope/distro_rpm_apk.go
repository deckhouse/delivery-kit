package shippedscope

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/package-url/packageurl-go"
)

const (
	rpmPurlType = "rpm"
	apkPurlType = "apk"
)

// rpm keeps its database in one of these, and a distribution that moved it leaves a symlink
// at the old place; an image holding real database files in both has two databases and
// neither is taken for the one rpm reads.
var rpmDatabaseDirs = []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"}

const (
	rpmSQLiteFile = "rpmdb.sqlite"
	rpmWALFile    = "rpmdb.sqlite-wal"
	// A database rpm could not switch to write-ahead logging keeps a rollback journal
	// instead, which is non-empty only while a transaction is unfinished.
	rpmJournalFile = "rpmdb.sqlite-journal"
	rpmBDBFile     = "Packages"
	rpmNDBFile     = "Packages.db"
)

// apk's database moved under /usr with the same contents.
var apkDatabaseFiles = []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"}

func isRPMOrAPKDatabase(file string) bool {
	if slices.Contains(apkDatabaseFiles, file) {
		return true
	}
	dir, base := path.Split(file)

	return slices.Contains(rpmDatabaseDirs, strings.TrimSuffix(dir, "/")) &&
		slices.Contains([]string{rpmSQLiteFile, rpmWALFile, rpmJournalFile, rpmBDBFile, rpmNDBFile}, base)
}

// ManagerPackageKey keys a package of the given package manager, named by its purl type.
// A dpkg package keeps the key DistroPackageKey gives it; another manager's is set apart, so
// that an rpm and a deb of the same name, version and architecture never stand for each other.
func ManagerPackageKey(manager, name, version, arch string) string {
	key := DistroPackageKey(name, version, arch)
	if manager == dpkgPurlType {
		return key
	}

	return manager + "\x00" + key
}

// readRPMDatabase adds what rpm records as installed. It reads the SQLite form rpm uses
// since 4.16 and the Berkeley DB hash form before it; the ndb form, a database left with
// unmerged write-ahead log, two databases at once, or one that does not read whole is not
// read at all, and rpm components then keep stating no whereabouts.
func readRPMDatabase(database *DistroDatabase, index *FileIndex, manifests map[string][]byte) {
	var dirs []string
	for file := range manifests {
		dir := path.Dir(file)
		if base := path.Base(file); base != rpmWALFile && base != rpmJournalFile && !slices.Contains(dirs, dir) && slices.Contains(rpmDatabaseDirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	if len(dirs) == 0 {
		return
	}
	packages, err := rpmDatabasePackages(dirs, manifests)
	if err != nil {
		database.Unread[rpmPurlType] = err.Error()

		return
	}
	entries := make(map[string]DistroPackage, len(packages))
	for _, pkg := range packages {
		key := ManagerPackageKey(rpmPurlType, pkg.Name, pkg.EVR(), pkg.Arch)
		if _, seen := entries[key]; seen {
			database.Unread[rpmPurlType] = fmt.Sprintf("rpm database records %s %s %s twice", pkg.Name, pkg.EVR(), pkg.Arch)

			return
		}
		entries[key] = distroPackageAt(index, rpmPurlType, pkg.Name, pkg.EVR(), pkg.Arch, pkg.Files)
	}
	database.addManager(rpmPurlType, entries)
}

func rpmDatabasePackages(dirs []string, manifests map[string][]byte) ([]rpmPackage, error) {
	if len(dirs) > 1 {
		return nil, fmt.Errorf("rpm databases in both %s", strings.Join(dirs, " and "))
	}
	dir := dirs[0]
	var forms []string
	for _, form := range []string{rpmSQLiteFile, rpmBDBFile, rpmNDBFile} {
		if _, ok := manifests[dir+"/"+form]; ok {
			forms = append(forms, form)
		}
	}
	if len(forms) != 1 {
		return nil, fmt.Errorf("rpm database in %s is kept in %d forms", dir, len(forms))
	}

	var blobs [][]byte
	switch forms[0] {
	case rpmNDBFile:
		return nil, errors.New("rpm ndb database is not read")
	case rpmSQLiteFile:
		if len(manifests[dir+"/"+rpmWALFile]) > 0 {
			return nil, errors.New("rpm SQLite database has an unmerged write-ahead log")
		}
		if len(manifests[dir+"/"+rpmJournalFile]) > 0 {
			return nil, errors.New("rpm SQLite database has an unfinished transaction journal")
		}
		var err error
		if blobs, err = sqliteTableBlobs(manifests[dir+"/"+rpmSQLiteFile], "Packages", 1); err != nil {
			return nil, err
		}
	case rpmBDBFile:
		values, err := bdbHashValues(manifests[dir+"/"+rpmBDBFile])
		if err != nil {
			return nil, err
		}
		// In header order, so that a build of the same image reports the same reason.
		for _, instance := range slices.Sorted(maps.Keys(values)) {
			blobs = append(blobs, values[instance])
		}
	}

	packages := make([]rpmPackage, 0, len(blobs))
	for _, blob := range blobs {
		pkg, err := parseRPMHeader(blob)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// readAPKDatabase adds what apk records as installed.
func readAPKDatabase(database *DistroDatabase, index *FileIndex, manifests map[string][]byte) {
	var found []string
	for _, file := range apkDatabaseFiles {
		if _, ok := manifests[file]; ok {
			found = append(found, file)
		}
	}
	if len(found) == 0 {
		return
	}
	if len(found) > 1 {
		database.Unread[apkPurlType] = "apk databases in both " + strings.Join(found, " and ")

		return
	}
	packages, err := parseAPKInstalled(manifests[found[0]])
	if err != nil {
		database.Unread[apkPurlType] = err.Error()

		return
	}
	entries := make(map[string]DistroPackage, len(packages))
	for _, pkg := range packages {
		key := ManagerPackageKey(apkPurlType, pkg.Name, pkg.Version, pkg.Arch)
		if _, seen := entries[key]; seen {
			database.Unread[apkPurlType] = fmt.Sprintf("apk database records %s %s %s twice", pkg.Name, pkg.Version, pkg.Arch)

			return
		}
		// The directories apk made count as declared, as dpkg's and rpm's lists count
		// theirs: a package of directories alone declares where it stands.
		entries[key] = distroPackageAt(index, apkPurlType, pkg.Name, pkg.Version, pkg.Arch, append(pkg.Dirs, pkg.Files...))
	}
	database.addManager(apkPurlType, entries)
}

func distroPackageAt(index *FileIndex, manager, name, version, arch string, declared []string) DistroPackage {
	resolved := make([]string, 0, len(declared))
	for _, file := range declared {
		resolved = append(resolved, resolveDirSymlinks(index, rootedPath(file)))
	}
	files, symlinks := collect(index, resolved)

	return DistroPackage{
		Manager: manager, Name: name, Version: version, Arch: arch,
		Files: files, Symlinks: symlinks, DeclaresFiles: len(declared) > 0,
	}
}

func (d *DistroDatabase) addManager(manager string, entries map[string]DistroPackage) {
	for key, entry := range entries {
		d.Packages[key] = entry
	}
	d.Managers[manager] = true
	d.Present = true
}

// purlPackageVersion is the version a purl names, spelled as the database keys it. rpm keys
// carry the epoch when there is one and never a zero one; a purl states it as a qualifier,
// or, from some tools, in front of the version. ok is false when the purl states no epoch at
// all: it then names the version without saying which epoch it means.
func purlPackageVersion(purl packageurl.PackageURL) (string, bool) {
	if purl.Type != rpmPurlType {
		return purl.Version, true
	}
	if epoch, version, found := strings.Cut(purl.Version, ":"); found {
		if epoch == "0" {
			return version, true
		}

		return purl.Version, true
	}
	epoch, stated := purl.Qualifiers.Map()["epoch"]
	if !stated {
		return purl.Version, false
	}
	if epoch == "" || epoch == "0" {
		return purl.Version, true
	}

	return epoch + ":" + purl.Version, true
}

// epochUnsettled answers whether rpm records name, for arch when one is given, at version
// under a nonzero epoch.
func (d *DistroDatabase) epochUnsettled(name, version, arch string) bool {
	for _, entry := range d.Packages {
		if entry.Manager == rpmPurlType && entry.Name == name && (arch == "" || entry.Arch == arch) &&
			strings.HasSuffix(entry.Version, ":"+version) {
			return true
		}
	}

	return false
}
