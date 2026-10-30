package nativegate

import (
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// bootstrapProjectionSource is the placeholder original every file of a bootstrap import
// is projected under, so that the destinations the copy lands can be read back off the
// projection the gate already applies to bindings.
const bootstrapProjectionSource = "bootstrap"

// ImportOriginal binds a subtree of a bootstrap source image to the prepared source its
// files were opened from. A bootstrap image describes no composition of its own, so the
// physical place a file sits in it says nothing about what it is: the recipe that imports
// it states which prepared source serves those bytes and under which path of it. The
// statement is held against the pinned Packet itself - only bytes the original still
// serves at the named path bind - so a wrong mapping binds nothing rather than claiming
// something.
//
// Root is a clean absolute path of the source image, OriginalPath the path of the Packet
// its contents stand at, "." naming the root of the Packet. The prepared source is named
// by the package identity the import source's own receipt pins it by.
type ImportOriginal struct {
	Root           string
	PackageName    string
	PackageVersion string
	OriginalPath   string
}

// bootstrapImportMatches binds the files of a bootstrap import source to the prepared
// sources that serve them: the ones its pm receipt accounts for where it installed them,
// and the ones the importing recipe maps by declaration. Nothing the source image says
// about itself is read.
func bootstrapImportMatches(ctx context.Context, e *sourceEvidence, imported SourceImport) (originalMatches, error) {
	if imported.BOM != nil {
		return nil, fmt.Errorf("no-data: a bootstrap import source describes no composition of its own, yet a document was read for it")
	}
	matches, err := e.installed(ctx, SourceSnapshot{Stage: "bootstrap import source", Index: imported.Index, Receipt: imported.Receipt})
	if err != nil {
		return nil, err
	}
	declared, err := declaredBootstrapMatches(ctx, e, imported)
	if err != nil {
		return nil, err
	}
	for name, bindings := range declared {
		matches[name] = sortedOriginalBindings(append(matches[name], bindings...))
	}

	return matches, nil
}

func declaredBootstrapMatches(ctx context.Context, e *sourceEvidence, imported SourceImport) (originalMatches, error) {
	if len(imported.Originals) == 0 {
		return nil, nil
	}
	if err := validateImportOriginals(imported.Originals); err != nil {
		return nil, err
	}
	packages, err := declaredBootstrapPackages(ctx, e, imported)
	if err != nil {
		return nil, err
	}

	matches := make(originalMatches)
	wanted := make(map[string]map[string]shippedscope.File)
	for _, name := range slices.Sorted(maps.Keys(imported.Index.Files)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		mapping, mapped := mappedImportOriginal(imported.Originals, name)
		if !mapped {
			continue
		}
		id := packages[declaredPackage{Name: mapping.PackageName, Version: mapping.PackageVersion}]
		relative, _ := pathUnder(mapping.Root, name)
		if name == mapping.Root {
			relative = "."
		}
		originalPath := path.Join(mapping.OriginalPath, relative)
		entry, err := e.resolved[id].Original.Lookup(originalPath)
		// A root holds whatever the source image put under it, the prepared source
		// included; a path the Packet does not serve with these very bytes is left
		// for whatever else accounts for the file.
		if err != nil || entry.SHA256 == "" || entry.SHA256 != imported.Index.Files[name].Digest {
			continue
		}

		if wanted[id] == nil {
			wanted[id] = make(map[string]shippedscope.File)
		}
		wanted[id][originalPath] = imported.Index.Files[name]
		matches[name] = []originalBinding{{Source: id, Path: originalPath}}
	}

	for _, id := range slices.Sorted(maps.Keys(wanted)) {
		if err := verifyOriginalFiles(ctx, e.resolved[id].Original, wanted[id]); err != nil {
			return nil, fmt.Errorf("original %q: %w", id, err)
		}
	}

	return matches, nil
}

// declaredPackage is the identity a mapping names a prepared source by.
type declaredPackage struct {
	Name    string
	Version string
}

// declaredBootstrapPackages resolves every prepared source the mappings name against the
// receipt of the import source image. The receipt is what pins the Packet - registry,
// platform and metadata - and the mapping only picks one of the sources it already
// accounts for, so no identity is invented here.
func declaredBootstrapPackages(ctx context.Context, e *sourceEvidence, imported SourceImport) (map[declaredPackage]string, error) {
	if imported.Receipt == nil {
		return nil, fmt.Errorf("no-data: the bootstrap import source carries no original source receipt the declared mappings could name")
	}

	wanted := make(map[declaredPackage]string)
	for _, mapping := range imported.Originals {
		wanted[declaredPackage{Name: mapping.PackageName, Version: mapping.PackageVersion}] = ""
	}
	for _, source := range imported.Receipt.Sources {
		metadata, err := readSourcePackage(source)
		if err != nil {
			return nil, err
		}
		identity := declaredPackage{Name: metadata.Name, Version: metadata.Version}
		if known, asked := wanted[identity]; !asked || known != "" {
			if asked {
				return nil, fmt.Errorf("no-data: the bootstrap import source opens %s %s more than once", identity.Name, identity.Version)
			}

			continue
		}
		resolved, err := e.resolve(ctx, source)
		if err != nil {
			return nil, err
		}
		wanted[identity] = resolved.ID
	}
	for _, identity := range slices.SortedFunc(maps.Keys(wanted), func(a, b declaredPackage) int {
		return strings.Compare(a.Name+"\x00"+a.Version, b.Name+"\x00"+b.Version)
	}) {
		if wanted[identity] == "" {
			return nil, fmt.Errorf("no-data: the bootstrap import source opens no prepared source %s %s", identity.Name, identity.Version)
		}
	}

	return wanted, nil
}

// mappedImportOriginal answers which declared mapping places a file of the source image.
// The most specific root wins: a tree is mapped as a whole and a part of it that stands
// somewhere else in the Packet is mapped beside it.
func mappedImportOriginal(originals []ImportOriginal, name string) (ImportOriginal, bool) {
	var found ImportOriginal
	mapped := false
	for _, mapping := range originals {
		if _, under := pathUnder(mapping.Root, name); !under && name != mapping.Root {
			continue
		}
		if mapped && len(found.Root) >= len(mapping.Root) {
			continue
		}
		found, mapped = mapping, true
	}

	return found, mapped
}

func validateImportOriginals(originals []ImportOriginal) error {
	roots := make(map[string]bool, len(originals))
	for _, mapping := range originals {
		if mapping.Root == "" || rootedImportPath(mapping.Root) != mapping.Root {
			return fmt.Errorf("invalid: the declared original root %q is not a clean rooted path", mapping.Root)
		}
		if mapping.PackageName == "" || mapping.PackageVersion == "" {
			return fmt.Errorf("invalid: the declared original root %q names no prepared source", mapping.Root)
		}
		if mapping.OriginalPath != "." {
			if err := originalPath(mapping.OriginalPath); err != nil {
				return fmt.Errorf("invalid: the declared original root %q: %w", mapping.Root, err)
			}
		}
		if roots[mapping.Root] {
			return fmt.Errorf("invalid: the declared original root %q is mapped more than once", mapping.Root)
		}
		roots[mapping.Root] = true
	}

	return nil
}

// bootstrapLandedFiles answers which regular files of the importing stage this import
// of a bootstrap source put there. Every one of them has to be accounted for by this
// image, so they are projected the way a binding is - by the directives of the copy, and
// only where the stage kept the bytes the copy landed - rather than guessed from where
// they ended up.
func bootstrapLandedFiles(ctx context.Context, imported SourceImport, before, after *shippedscope.FileIndex) (map[string]bool, error) {
	asked := make(originalMatches, len(imported.Index.Files))
	for name := range imported.Index.Files {
		asked[name] = []originalBinding{{Source: bootstrapProjectionSource, Path: strings.TrimPrefix(name, "/")}}
	}
	landed, err := importOriginalMatches(ctx, imported.Index, asked, before, after, imported.Scope)
	if err != nil {
		return nil, err
	}

	files := make(map[string]bool, len(landed))
	for destination := range landed {
		files[destination] = true
	}

	return files, nil
}

// carryBootstrap keeps the obligation of a bootstrap source on the bytes it landed, for
// as long as the build still holds them. A stage that moves or copies such a file carries
// the obligation with it - the bytes are the ones the import brought, wherever they now
// sit - and bytes a stage replaced are that stage's own doing, answered for as anything
// else it makes is.
func (e *sourceEvidence) carryBootstrap(index *shippedscope.FileIndex) map[string]bool {
	landed := make(map[shippedscope.File]bool, len(e.bootstrap))
	for name := range e.bootstrap {
		if file, held := e.index.Files[name]; held {
			landed[file] = true
		}
	}

	carried := make(map[string]bool, len(e.bootstrap))
	for name, file := range index.Files {
		if landed[file] {
			carried[name] = true
		}
	}

	return carried
}
