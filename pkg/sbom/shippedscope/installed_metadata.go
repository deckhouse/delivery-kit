package shippedscope

import (
	"context"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/werf/logboek"
)

const (
	maxInstalledMetadataFileBytes int64 = 4 << 20
	maxInstalledMetadataBytes     int64 = 64 << 20
	maxInstalledMetadataFiles           = 65536
)

// InstalledPackageFiles maps logical installation paths to the regular files to read,
// so symlink targets can be materialized without losing their installation layout.
// These layouts establish inventory, not directive ownership or runtime reachability.
func InstalledPackageFiles(ctx context.Context, index *FileIndex) map[Ecosystem]map[string]string {
	paths := slices.AppendSeq(slices.Collect(maps.Keys(index.Files)), maps.Keys(index.Symlinks))
	slices.Sort(paths)
	paths = slices.Compact(paths)

	var candidates []string
	for _, file := range paths {
		if installedMetadataCandidate(file) {
			candidates = append(candidates, file)
		}
	}

	projected := 0
links:
	for _, link := range slices.Sorted(maps.Keys(index.Symlinks)) {
		target, ok := resolveInstalledMetadataPath(index, link)
		if !ok {
			continue
		}
		if _, regular := index.Files[target]; regular {
			continue
		}
		prefix := strings.TrimSuffix(target, "/") + "/"
		start, _ := slices.BinarySearch(paths, prefix)
		for i := start; i < len(paths) && strings.HasPrefix(paths[i], prefix); i++ {
			logical := rootedJoin(link, strings.TrimPrefix(paths[i], prefix))
			if !installedMetadataCandidate(logical) {
				continue
			}
			if projected >= maxInstalledMetadataFiles {
				logboek.Context(ctx).Warn().LogF("WARNING: installed package metadata exceeds the linked path limit; the inventory may be incomplete\n")
				break links
			}
			candidates = append(candidates, logical)
			projected++
		}
	}
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)

	roots := make(map[string]Ecosystem)
	standalone := make(map[string]Ecosystem)
	hasPython := false
	for _, file := range candidates {
		if _, _, ok := installedMetadataFile(index, file); !ok {
			continue
		}

		dir := path.Dir(file)
		base := path.Base(file)
		lowerDir := strings.ToLower(dir)
		switch {
		case isNodePackageManifest(file):
			roots[dir] = EcosystemJavaScript
		case base == "METADATA" && strings.HasSuffix(lowerDir, ".dist-info"):
			roots[dir] = EcosystemPython
			hasPython = true
		case base == "PKG-INFO" && strings.HasSuffix(lowerDir, ".egg-info"):
			_, _, recorded := installedMetadataFile(index, path.Join(dir, "installed-files.txt"))
			parent := path.Base(path.Dir(dir))
			if recorded || parent == "site-packages" || parent == "dist-packages" {
				roots[dir] = EcosystemPython
				hasPython = true
			}
		case strings.HasSuffix(base, ".egg-info") && (path.Base(dir) == "site-packages" || path.Base(dir) == "dist-packages"):
			standalone[file] = EcosystemPython
			hasPython = true
		case strings.HasSuffix(base, ".rockspec"):
			prefix, luaVersion, ok := luarocksTree(dir)
			if !ok {
				continue
			}
			name, version := path.Base(path.Dir(dir)), path.Base(dir)
			expectedDir := path.Join(prefix, "lib", "luarocks", "rocks-"+luaVersion, name, version)
			if dir == expectedDir && base == name+"-"+version+".rockspec" {
				standalone[file] = EcosystemLua
			}
		}
	}

	selected := make(map[Ecosystem]map[string]string)
	remaining := maxInstalledMetadataBytes
	count := 0
	for _, file := range candidates {
		ecosystem := standalone[file]
		if hasPython && path.Base(file) == "pyvenv.cfg" {
			ecosystem = EcosystemPython
		}
		for dir := path.Dir(file); dir != "/"; dir = path.Dir(dir) {
			rootEcosystem, ok := roots[dir]
			if !ok {
				continue
			}
			if rootEcosystem == EcosystemPython || (dir == path.Dir(file) && (path.Base(file) == "package.json" || installedLicenseFile(path.Base(file)))) {
				ecosystem = rootEcosystem
			}
			break
		}
		if ecosystem == "" {
			continue
		}
		if count >= maxInstalledMetadataFiles {
			logboek.Context(ctx).Warn().LogF("WARNING: installed package metadata exceeds the file count limit; the inventory may be incomplete\n")
			break
		}

		source, entry, ok := installedMetadataFile(index, file)
		if !ok {
			logboek.Context(ctx).Warn().LogF("WARNING: installed package metadata %s cannot be resolved in the image; the inventory may be incomplete\n", file)
			continue
		}
		if entry.Size > maxInstalledMetadataFileBytes || entry.Size > remaining {
			logboek.Context(ctx).Warn().LogF("WARNING: installed package metadata %s exceeds the scan size limit; the inventory may be incomplete\n", file)
			continue
		}
		remaining -= entry.Size
		count++
		if selected[ecosystem] == nil {
			selected[ecosystem] = make(map[string]string)
		}
		selected[ecosystem][file] = source
	}

	return selected
}

func installedMetadataCandidate(file string) bool {
	lower := strings.ToLower(file)
	return isNodePackageManifest(file) ||
		(installedLicenseFile(path.Base(file)) && isNodePackageManifest(path.Join(path.Dir(file), "package.json"))) ||
		strings.Contains(lower, ".dist-info/") || strings.Contains(lower, ".egg-info/") ||
		strings.HasSuffix(file, ".egg-info") || strings.HasSuffix(file, ".rockspec") || path.Base(file) == "pyvenv.cfg"
}

func installedLicenseFile(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{"license", "licence", "unlicense", "unlicence", "mit-license", "mit-licence", "copying", "notice", "copyright"} { //nolint:misspell // Package filenames use both spellings.
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func installedMetadataFile(index *FileIndex, file string) (string, File, bool) {
	source, ok := resolveInstalledMetadataPath(index, file)
	if !ok {
		return "", File{}, false
	}
	entry, ok := index.Files[source]
	return source, entry, ok
}

func resolveInstalledMetadataPath(index *FileIndex, file string) (string, bool) {
	for range 40 {
		replaced := false
		for prefix := file; prefix != "/"; prefix = path.Dir(prefix) {
			target, ok := index.Symlinks[prefix]
			if !ok {
				continue
			}
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(prefix), target)
			}
			file = rootedPath(path.Join(target, strings.TrimPrefix(file, prefix)))
			replaced = true
			break
		}
		if !replaced {
			return file, true
		}
	}
	return "", false
}
