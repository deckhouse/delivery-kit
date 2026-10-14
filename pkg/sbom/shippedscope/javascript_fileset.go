package shippedscope

import (
	"encoding/json"
	"path"
	"strings"
)

const (
	nodeModulesDir    = "/node_modules/"
	distributionJSDir = "/usr/share/nodejs/"
)

// javascriptFilesets draws a package's boundary around the directory holding its
// package.json, minus the package trees nested inside it: npm installs a second copy of a
// dependency under its dependent when versions conflict, and those files belong to that
// copy, not to the package above it.
func javascriptFilesets(index *FileIndex, manifests map[string][]byte) []Fileset {
	var filesets []Fileset

	for manifest, body := range manifests {
		if !isNodePackageManifest(manifest) {
			continue
		}

		var declaration struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(body, &declaration); err != nil {
			continue
		}
		if declaration.Name == "" || declaration.Version == "" {
			continue
		}

		root := path.Dir(manifest)

		files, symlinks := collect(index, packageTreePaths(index, root))

		filesets = append(filesets, Fileset{
			Ecosystem: EcosystemJavaScript,
			Name:      declaration.Name,
			Version:   declaration.Version,
			Root:      root,
			Files:     files,
			Symlinks:  symlinks,
		})
	}

	return filesets
}

func isNodePackageManifest(file string) bool {
	if path.Base(file) != "package.json" {
		return false
	}

	dir := path.Dir(file) + "/"

	return strings.Contains(dir, nodeModulesDir) || strings.Contains(dir, distributionJSDir)
}

func packageTreePaths(index *FileIndex, root string) []string {
	prefix := root + "/"

	var paths []string
	for file := range index.Files {
		if strings.HasPrefix(file, prefix) && !strings.Contains(strings.TrimPrefix(file, prefix), "node_modules/") {
			paths = append(paths, file)
		}
	}
	for file := range index.Symlinks {
		if strings.HasPrefix(file, prefix) && !strings.Contains(strings.TrimPrefix(file, prefix), "node_modules/") {
			paths = append(paths, file)
		}
	}

	return paths
}
