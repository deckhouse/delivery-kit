package shippedscope

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/werf/logboek"
)

const (
	pmIndexPath = "/var/lib/pm/index.json"
	pmFilesPath = "/var/lib/pm/files.json"
)

// pmFileList is what pm writes beside its index once it records the files it unpacks:
// one entry per installed package, its version, and the regular files and symlinks the
// package put into the image.
type pmFileList map[string]struct {
	Version  string            `json:"version"`
	Files    map[string]string `json:"files"`
	Symlinks map[string]string `json:"symlinks"`
}

// osPMFilesets takes a package's boundary from the list pm wrote while unpacking it. The
// digest pm recorded is left aside: a file an install hook rewrote afterwards ships with
// the content the image holds now, which is what the index gives.
//
// pm records a file under the path its archive spells, and the image holds it where that
// path leads once the directory symlinks the base lays down are followed — a package whose
// archive says /usr/lib64 lands in /usr/lib when /usr/lib64 points there. The declared
// paths are resolved through those symlinks before the index is consulted, so that the
// fileset names the file where the image has it.
//
// An image installed by a pm too old to write the list yields no os-pm filesets, a
// warning, and the second result set: breaking every build still on an older base would
// be the worse outcome.
func osPMFilesets(ctx context.Context, index *FileIndex, manifests map[string][]byte) ([]Fileset, bool, error) {
	body, ok := manifests[pmFilesPath]
	if !ok {
		if _, indexed := index.Files[pmIndexPath]; !indexed {
			return nil, false, nil
		}

		logboek.Context(ctx).Warn().LogF("WARNING: %s is present but %s is not: the image was installed by a pm that records no file lists, os-pm packages are left out of the filesets\n", pmIndexPath, pmFilesPath)

		return nil, true, nil
	}

	var list pmFileList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", pmFilesPath, err)
	}

	var filesets []Fileset
	for _, name := range slices.Sorted(maps.Keys(list)) {
		entry := list[name]
		declared := make([]string, 0, len(entry.Files)+len(entry.Symlinks))
		for file := range entry.Files {
			declared = append(declared, resolveDirSymlinks(index, rootedPath(file)))
		}
		for link := range entry.Symlinks {
			declared = append(declared, resolveDirSymlinks(index, rootedPath(link)))
		}

		files, symlinks := collect(index, declared)

		filesets = append(filesets, Fileset{
			Ecosystem:     EcosystemOSPM,
			Name:          name,
			Version:       entry.Version,
			Files:         files,
			Symlinks:      symlinks,
			DeclaresFiles: len(declared) > 0,
		})
	}

	return filesets, false, nil
}

const maxDirSymlinkHops = 40

// resolveDirSymlinks follows every symlink among the directories above the leaf of a rooted
// path, the leaf itself excluded: a symlink there is the entry the fileset wants, not a
// detour. Targets are taken as the image spells them, absolute or relative to the link's
// own directory, and a ".." inside one steps out of whatever the components before it
// resolved to, as the kernel would walk it. A chain that does not settle within the hop
// budget is returned as it stands.
func resolveDirSymlinks(index *FileIndex, file string) string {
	dir, rest := "/", strings.TrimPrefix(file, "/")
	hops := 0
	for {
		name, tail, hasTail := strings.Cut(rest, "/")
		if !hasTail {
			return path.Join(dir, name)
		}

		switch name {
		case "", ".":
			rest = tail

			continue
		case "..":
			dir, rest = path.Dir(dir), tail

			continue
		}

		current := path.Join(dir, name)
		target, ok := index.Symlinks[current]
		if !ok {
			dir, rest = current, tail

			continue
		}

		hops++
		if hops > maxDirSymlinkHops {
			return file
		}

		if path.IsAbs(target) {
			dir = "/"
		}
		rest = strings.TrimPrefix(target, "/") + "/" + tail
	}
}
