package shippedscope

import (
	"context"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Ecosystem string

const (
	EcosystemOSPM       Ecosystem = "os-pm"
	EcosystemPython     Ecosystem = "python"
	EcosystemJavaScript Ecosystem = "javascript"
	EcosystemLua        Ecosystem = "lua"
)

// Fileset is one installed copy of a component and the files the image gives it. npm keeps
// several copies of one version under different paths, so Root tells them apart; the rule
// that consumes this treats them as one owner.
type Fileset struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	Root      string
	Files     map[string]File
	Symlinks  map[string]string
}

// CollectFilesets reads the image once and answers, for every component an ecosystem
// installed into it, which files are that component's.
//
// Each ecosystem draws the boundary itself, and none of them draw it around a directory:
// Python takes the paths its RECORD declares, JavaScript takes a package directory minus
// the nested package trees inside it, Lua takes the paths its rock manifest declares across
// the install roots they land in, and os-pm takes the list its package manager wrote. The
// digests always come from the image, never from the manifest that names the file.
func CollectFilesets(ctx context.Context, img v1.Image) ([]Fileset, error) {
	index, manifests, err := indexImageFiles(ctx, img, isFilesetManifest)
	if err != nil {
		return nil, err
	}

	filesets, err := osPMFilesets(ctx, index, manifests)
	if err != nil {
		return nil, err
	}

	filesets = append(filesets, pythonFilesets(index, manifests)...)
	filesets = append(filesets, javascriptFilesets(index, manifests)...)
	filesets = append(filesets, luaFilesets(index, manifests)...)

	return filesets, nil
}

func isFilesetManifest(file string) bool {
	return file == pmFilesPath ||
		strings.HasSuffix(file, distInfoRecordSuffix) ||
		isNodePackageManifest(file) ||
		path.Base(file) == rockManifestName
}

// collect gathers what the image holds at the given paths. A path a manifest declares but
// the image no longer holds is left out: the fileset describes what shipped, not what was
// installed.
func collect(index *FileIndex, paths []string) (map[string]File, map[string]string) {
	files := make(map[string]File)
	symlinks := make(map[string]string)

	for _, file := range paths {
		if entry, ok := index.Files[file]; ok {
			files[file] = entry

			continue
		}

		if target, ok := index.Symlinks[file]; ok {
			symlinks[file] = target
		}
	}

	return files, symlinks
}

func rootedJoin(dir, rel string) string {
	return rootedPath(path.Join(dir, rel))
}
