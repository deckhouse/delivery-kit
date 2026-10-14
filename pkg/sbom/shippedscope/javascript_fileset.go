package shippedscope

import (
	"encoding/json"
	"path"
	"strings"
)

const nodeModulesDir = "node_modules"

// Where a distribution's packages for Node.js land when installed by the system package
// manager rather than npm.
var distributionNodeDirs = []string{"/usr/share/nodejs", "/usr/lib/nodejs"}

// javascriptFilesets draws a package's boundary around the directory holding its
// package.json, minus the package trees nested inside it: npm installs a second copy of a
// dependency under its dependent when versions conflict, and those files belong to that
// copy, not to the package above it.
//
// Only a package.json sitting where an installer puts packages counts. Packages ship
// fixtures and examples with a package.json of their own, and those stay the package's
// files. A Yarn PnP cache holds packages as archives and is not read.
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
			Files:     files,
			Symlinks:  symlinks,
		})
	}

	return filesets
}

// isNodePackageManifest accepts <packages>/<name>/package.json and
// <packages>/@<scope>/<name>/package.json, where <packages> is any node_modules
// directory or one of the distribution directories.
func isNodePackageManifest(file string) bool {
	if path.Base(file) != "package.json" {
		return false
	}

	packages := path.Dir(path.Dir(file))
	if strings.HasPrefix(path.Base(packages), "@") {
		packages = path.Dir(packages)
	}

	if path.Base(packages) == nodeModulesDir {
		return true
	}

	for _, dir := range distributionNodeDirs {
		if packages == dir {
			return true
		}
	}

	return false
}

func packageTreePaths(index *FileIndex, root string) []string {
	var paths []string
	for file := range index.Files {
		if inPackageTree(file, root) {
			paths = append(paths, file)
		}
	}
	for file := range index.Symlinks {
		if inPackageTree(file, root) {
			paths = append(paths, file)
		}
	}

	return paths
}

func inPackageTree(file, root string) bool {
	if !hasPathPrefix(file, root) {
		return false
	}

	for _, segment := range strings.Split(path.Dir(strings.TrimPrefix(file, root+"/")), "/") {
		if segment == nodeModulesDir {
			return false
		}
	}

	return true
}
