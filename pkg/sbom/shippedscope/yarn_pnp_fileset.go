package shippedscope

import (
	"cmp"
	"context"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/werf/logboek"
)

const (
	yarnLockName              = "yarn.lock"
	yarnLockMetadataKey       = "__metadata"
	maxYarnLockBytes    int64 = 32 << 20
	yarnArchiveSuffix         = ".zip"
)

// Yarn 3 writes the bare digest; Yarn 4 prefixes it with the cache key.
var yarnChecksumPattern = regexp.MustCompile(`^(?:[0-9A-Za-z]+/)?([0-9a-f]{128})$`)

// yarnPnPFilesets gives each package a Yarn Berry lockfile resolved from the npm registry the
// cache archives the image holds byte for byte: the lockfile checksum is the SHA-512 of the
// archive, wherever in the image it sits. A package whose archive the image does not hold
// gets no fileset, so it is not shown absent by a lockfile that outlived its cache. Packages
// from any other source — a workspace, a patch, a git repository, a local path — have no
// fileset either: their archive is not the published package. Neither does an archive inside
// the tree of an installed package, nor anywhere else holding the bytes of such a file: they
// are already that package's, and two owners of one content let the proven one disprove the
// other.
func yarnPnPFilesets(ctx context.Context, index *FileIndex, manifests map[string][]byte, installed []Fileset) []Fileset {
	owned := make(map[string]bool)
	for _, fileset := range installed {
		for _, file := range fileset.Files {
			owned[file.Digest] = true
		}
	}

	archives := make(map[string][]string)
	for file, entry := range index.Files {
		if entry.sha512 != "" && strings.HasSuffix(file, yarnArchiveSuffix) && !owned[entry.Digest] {
			archives[entry.sha512] = append(archives[entry.sha512], file)
		}
	}

	declared := make(map[[2]string]map[string]bool)
	for _, lockfile := range slices.Sorted(maps.Keys(index.Files)) {
		if path.Base(lockfile) != yarnLockName {
			continue
		}

		body, ok := manifests[lockfile]
		if !ok || index.linked[lockfile] || int64(len(body)) > maxYarnLockBytes {
			logboek.Context(ctx).Warn().LogF("WARNING: Yarn lockfile %s is over %d bytes or a hardlink and is not read; the Yarn Plug'n'Play archives it names are not attributed to their packages\n", lockfile, maxYarnLockBytes)

			continue
		}

		var entries map[string]struct {
			Resolution string `yaml:"resolution"`
			Checksum   string `yaml:"checksum"`
		}
		if err := yaml.Unmarshal(body, &entries); err != nil {
			logboek.Context(ctx).Debug().LogF("Yarn lockfile %s is not read: %s\n", lockfile, err)

			continue
		}
		if _, ok := entries[yarnLockMetadataKey]; !ok {
			continue
		}

		for _, entry := range entries {
			name, version, ok := npmResolution(entry.Resolution)
			if !ok {
				continue
			}
			checksum := yarnChecksumPattern.FindStringSubmatch(entry.Checksum)
			if checksum == nil {
				continue
			}

			pkg := [2]string{name, version}
			for _, archive := range archives[checksum[1]] {
				if declared[pkg] == nil {
					declared[pkg] = make(map[string]bool)
				}
				declared[pkg][archive] = true
			}
		}
	}

	filesets := make([]Fileset, 0, len(declared))
	for _, pkg := range slices.SortedFunc(maps.Keys(declared), func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	}) {
		files, symlinks := collect(index, slices.Sorted(maps.Keys(declared[pkg])))
		filesets = append(filesets, Fileset{
			Ecosystem:     EcosystemJavaScript,
			Name:          pkg[0],
			Version:       pkg[1],
			Files:         files,
			Symlinks:      symlinks,
			DeclaresFiles: true,
		})
	}

	return filesets
}

// npmResolution reads a Berry locator such as "@babel/core@npm:7.28.0".
func npmResolution(resolution string) (string, string, bool) {
	if resolution == "" {
		return "", "", false
	}

	at := strings.Index(resolution[1:], "@")
	if at < 0 {
		return "", "", false
	}
	name := resolution[:at+1]
	version, ok := strings.CutPrefix(resolution[at+2:], "npm:")
	if !ok || !npmNamePattern.MatchString(name) || !npmVersionPattern.MatchString(version) {
		return "", "", false
	}

	return name, version, true
}
