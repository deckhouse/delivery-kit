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
// several copies of one version under different paths, so one (Ecosystem, Name, Version)
// can appear more than once; the rule that consumes this treats them as one owner.
type Fileset struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	Files     map[string]File
	Symlinks  map[string]string
}

type Filesets struct {
	Filesets []Fileset
	// OSPMFileListMissing is set when the image carries os-pm packages but was installed
	// by a pm that recorded no file list for them, so none of them has a fileset here. A
	// consumer that would drop a component without a fileset must not do so for os-pm then.
	OSPMFileListMissing bool
}

// CollectFilesets reads the image once and answers, for every component an ecosystem
// installed into it, which files are that component's.
//
// Each ecosystem draws the boundary itself, and none of them draw it around a directory:
// Python takes the paths its RECORD declares, JavaScript takes a package directory minus
// the nested package trees inside it, Lua takes the paths its rock manifest declares across
// the install roots they land in, and os-pm takes the list its package manager wrote. The
// digests always come from the image, never from the manifest that names the file.
//
// A component installed some other way — a Python egg-info, a LuaRocks 2 tree, a Yarn PnP
// cache — has no fileset, and this says nothing about whether it shipped.
func CollectFilesets(ctx context.Context, img v1.Image) (*Filesets, error) {
	index, manifests, err := indexImageFiles(ctx, img, isFilesetManifest)
	if err != nil {
		return nil, err
	}

	osPM, missing, err := osPMFilesets(ctx, index, manifests)
	if err != nil {
		return nil, err
	}

	filesets := &Filesets{
		Filesets:            osPM,
		OSPMFileListMissing: missing,
	}
	filesets.Filesets = append(filesets.Filesets, pythonFilesets(index, manifests)...)
	filesets.Filesets = append(filesets.Filesets, javascriptFilesets(index, manifests)...)
	filesets.Filesets = append(filesets.Filesets, luaFilesets(index, manifests)...)

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

func hasPathPrefix(file, dir string) bool {
	return strings.HasPrefix(file, dir+"/")
}
