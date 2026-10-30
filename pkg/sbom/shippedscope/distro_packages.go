package shippedscope

import (
	"context"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// DistroPackage is one entry of the package database the image's own distribution keeps:
// what it says is installed, and the files it recorded for it.
type DistroPackage struct {
	Name    string
	Version string
	Arch    string
	// Files are the paths the database recorded, as the image holds them. A package
	// whose database entry lists none has Files empty and DeclaresFiles false, which is
	// a different thing from one whose listed files are all gone.
	Files         map[string]File
	Symlinks      map[string]string
	DeclaresFiles bool
}

// DistroDatabase is what the image's own distribution records about itself.
type DistroDatabase struct {
	// Packages is what the database says is installed, keyed by DistroPackageKey.
	Packages map[string]DistroPackage
	// Index is the reading of the image that produced them, so that a consumer needing
	// a path the database did not name does not read the image again.
	Index *FileIndex
	// Present says whether the image carries a database this can read at all. An image
	// without one - built from scratch, or installed by a manager whose database is not
	// read here - says nothing about any package, and nothing may be concluded from its
	// silence.
	Present bool
}

// DistroPackages reads the package database of the image's own distribution: what dpkg
// records under /var/lib/dpkg, in the usual single-status form and in the per-package
// status.d form a distroless image carries.
//
// It is read in strict convergence alone, to place the package components an image
// inherits from its base's SBOM - the deb purls of a base this project did not build.
// Those components arrive stating no whereabouts, and an image importing a part of such
// an image can place none of them; the database the base itself carries is the one record
// of where they stand.
//
// What the database says is read as a fact about the image and nothing more: the files it
// names are looked up in the image, the digests come from the image, and a package the
// database does not mention at all is absent from it. Nothing here decides what a package
// is made of - that remains the supplier's claim, and a compiled file still answers with
// its own record - only where its files are.
//
// rpm and apk databases are not read. rpm keeps its own in sqlite or Berkeley DB, which
// nothing in this project opens, and writing a reader for either is not something to do
// on the way past; apk's is not read for the same reason. Components of those two keep
// stating no whereabouts, and a partial import of an image carrying them yields no data,
// which is what it did before this.
func DistroPackages(ctx context.Context, img v1.Image) (*DistroDatabase, error) {
	index, manifests, err := indexImageFiles(ctx, img, isDistroPackageDatabase)
	if err != nil {
		return nil, err
	}

	database := &DistroDatabase{Packages: make(map[string]DistroPackage), Index: index}
	for file := range manifests {
		if dpkgStatusFile(file) {
			database.Present = true

			break
		}
	}
	for _, entry := range dpkgStatusEntries(manifests) {
		declared := dpkgFileList(manifests, entry)
		resolved := make([]string, 0, len(declared))
		for _, file := range declared {
			resolved = append(resolved, resolveDirSymlinks(index, rootedPath(file)))
		}
		files, symlinks := collect(index, resolved)
		database.Packages[DistroPackageKey(entry.Name, entry.Version, entry.Arch)] = DistroPackage{
			Name: entry.Name, Version: entry.Version, Arch: entry.Arch,
			Files: files, Symlinks: symlinks, DeclaresFiles: len(declared) > 0,
		}
	}

	return database, nil
}

// DistroPackageKey keys a package by everything that tells it apart from another build of
// the same name: the same name at another version, or the same name and version built for
// another architecture, is a different package.
func DistroPackageKey(name, version, arch string) string {
	return name + "\x00" + version + "\x00" + arch
}

const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	dpkgStatusDir  = "/var/lib/dpkg/status.d"
	dpkgInfoDir    = "/var/lib/dpkg/info"
)

func isDistroPackageDatabase(file string) bool {
	switch {
	case file == dpkgStatusPath:
		return true
	case hasPathPrefix(file, dpkgStatusDir):
		// The per-package form keeps the stanza and its file list side by side.
		return true
	case hasPathPrefix(file, dpkgInfoDir):
		// The single-status form keeps one list per package, and the md5sums beside
		// it describe the bytes that shipped rather than what the image holds.
		return strings.HasSuffix(file, ".list")
	}

	return false
}

// dpkgStatusFile answers whether this is a file the database states installed packages in,
// as against the file lists kept beside them.
func dpkgStatusFile(file string) bool {
	if file == dpkgStatusPath {
		return true
	}

	return hasPathPrefix(file, dpkgStatusDir) && !strings.HasSuffix(file, ".md5sums")
}

type dpkgEntry struct {
	Name    string
	Version string
	Arch    string
	// Source is the file the entry was read from, which is where its own file list sits
	// when the database keeps one per package.
	Source string
}

// dpkgStatusEntries reads the installed packages out of both forms of the database. Only
// an entry whose files are in the image counts: a package removed but not purged, or never
// unpacked at all, keeps a stanza that describes nothing the image holds.
func dpkgStatusEntries(manifests map[string][]byte) []dpkgEntry {
	var entries []dpkgEntry
	for file, body := range manifests {
		if !dpkgStatusFile(file) {
			continue
		}
		for _, stanza := range strings.Split(string(body), "\n\n") {
			entry, ok := dpkgStanza(stanza)
			if !ok {
				continue
			}
			entry.Source = file
			entries = append(entries, entry)
		}
	}

	return entries
}

func dpkgStanza(stanza string) (dpkgEntry, bool) {
	var entry dpkgEntry
	installed := false
	for _, line := range strings.Split(stanza, "\n") {
		// A continuation line belongs to the field above it and never carries one.
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch name {
		case "Package":
			entry.Name = value
		case "Version":
			entry.Version = value
		case "Architecture":
			entry.Arch = value
		case "Status":
			// "want error state"; only the last word says whether the files are
			// there. They are, in every state but the two that mean the package
			// was never unpacked or has been removed: a half-installed, unpacked,
			// half-configured or triggers-awaiting package has its files on disk.
			fields := strings.Fields(value)
			installed = len(fields) > 0 && fields[len(fields)-1] != "not-installed" && fields[len(fields)-1] != "config-files"
		}
	}

	return entry, installed && entry.Name != "" && entry.Version != ""
}

// dpkgFileList reads the paths the database recorded for one package. The single-status
// database keeps them in info/, under the package name and, for a package of a foreign
// architecture, under name:arch; the per-package form keeps an md5sums file beside the
// stanza itself, named after it.
//
// A package whose list names nothing but the directories dpkg made for it - "/." and the
// like - declares no files, which is the same answer as a package with no list at all:
// nothing here can say where it stands.
func dpkgFileList(manifests map[string][]byte, entry dpkgEntry) []string {
	if entry.Source != dpkgStatusPath {
		return md5sumsPaths(manifests[entry.Source+".md5sums"])
	}

	body, ok := manifests[dpkgInfoDir+"/"+entry.Name+":"+entry.Arch+".list"]
	if !ok {
		body, ok = manifests[dpkgInfoDir+"/"+entry.Name+".list"]
	}
	if !ok {
		return nil
	}

	var files []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		// dpkg lists the directories it made as well as the files it put in them;
		// "/." is how it spells the root.
		if line == "" || line == "/." {
			continue
		}
		files = append(files, line)
	}

	return files
}

// md5sumsPaths reads the paths out of an md5sums list, which spells them relative to the
// root. The digests beside them are of the bytes the package shipped, not of what the
// image holds now, and are not read.
func md5sumsPaths(bodies ...[]byte) []string {
	var files []string
	for _, body := range bodies {
		for _, line := range strings.Split(string(body), "\n") {
			_, file, found := strings.Cut(strings.TrimSpace(line), " ")
			if !found {
				continue
			}
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			files = append(files, file)
		}
	}

	return files
}
