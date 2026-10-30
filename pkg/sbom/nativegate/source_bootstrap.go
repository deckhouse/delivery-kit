package nativegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// bootstrapProjectionSource is the placeholder original every file of a bootstrap import
// is projected under, so that the destinations the copy lands can be read back off the
// projection the gate already applies to bindings.
const bootstrapProjectionSource = "bootstrap"

// bootstrapProperty carries the paths this image holds that came out of a bootstrap
// source. The obligation they put on the image does not end with the build that imported
// them: an image built FROM this one, or one importing these paths out of it, answers for
// them exactly as this one does, and only the published document can tell it so. The
// property is private to DK and travels with the SBOM, never as an image label.
const bootstrapProperty = "dk:bootstrap/v1"

// bootstrapMarks is the published form of those paths.
type bootstrapMarks struct {
	Schema string   `json:"schema"`
	Paths  []string `json:"paths"`
}

func readBootstrapMarks(bom *cdx.BOM) (map[string]bool, error) {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Properties == nil {
		return nil, nil
	}
	var marks map[string]bool
	for _, property := range *bom.Metadata.Properties {
		if property.Name != bootstrapProperty {
			if strings.HasPrefix(property.Name, "dk:bootstrap/") {
				return nil, fmt.Errorf("unsupported inherited bootstrap marks property %s", property.Name)
			}

			continue
		}
		if marks != nil {
			return nil, fmt.Errorf("invalid: duplicate bootstrap marks")
		}
		var decoded bootstrapMarks
		if err := decode([]byte(property.Value), &decoded); err != nil {
			return nil, fmt.Errorf("invalid bootstrap marks: %w", err)
		}
		if decoded.Schema != bootstrapProperty {
			return nil, fmt.Errorf("no-data: incomplete or unsupported bootstrap marks")
		}
		marks = make(map[string]bool, len(decoded.Paths))
		for _, name := range decoded.Paths {
			if name == "" || rootedImportPath(name) != name {
				return nil, fmt.Errorf("invalid: bootstrap mark %q is not a clean rooted path", name)
			}
			marks[name] = true
		}
	}

	return marks, nil
}

// heldBootstrapMarks keeps the marks of a document for the paths the snapshot it describes
// actually holds as regular files. A path the image no longer has carries no obligation.
func heldBootstrapMarks(marks map[string]bool, index *shippedscope.FileIndex) map[string]bool {
	held := make(map[string]bool, len(marks))
	for name := range marks {
		if _, exists := index.Files[name]; exists {
			held[name] = true
		}
	}

	return held
}

func bootstrapMarksProperty(marks map[string]bool) (cdx.Property, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(bootstrapMarks{Schema: bootstrapProperty, Paths: slices.Sorted(maps.Keys(marks))}); err != nil {
		return cdx.Property{}, err
	}

	return cdx.Property{Name: bootstrapProperty, Value: string(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))}, nil
}

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

// declaredBootstrapPackages resolves every prepared source the mappings name against what
// the import source image itself stands on: the sources its pm receipt pins, and the ones
// its own recipe declares its stages compile. The first are what pm opened there; the
// second are what the build of that image was given, which is the only account of the
// source a self-built toolchain was made from. Either way the identity comes from a pinned
// Packet, not from the mapping, which only picks one of them; a name the two accounts
// disagree about picks nothing.
func declaredBootstrapPackages(ctx context.Context, e *sourceEvidence, imported SourceImport) (map[declaredPackage]string, error) {
	if imported.Receipt == nil && len(imported.Packages) == 0 {
		return nil, fmt.Errorf("no-data: the bootstrap import source carries neither an original source receipt nor a declared prepared source the mappings could name")
	}

	wanted := make(map[declaredPackage]string)
	for _, mapping := range imported.Originals {
		wanted[declaredPackage{Name: mapping.PackageName, Version: mapping.PackageVersion}] = ""
	}
	if imported.Receipt != nil {
		for _, source := range imported.Receipt.Sources {
			metadata, err := readSourcePackage(source)
			if err != nil {
				return nil, err
			}
			identity := declaredPackage{Name: metadata.Name, Version: metadata.Version}
			known, asked := wanted[identity]
			if !asked {
				continue
			}
			if known != "" {
				return nil, fmt.Errorf("no-data: the bootstrap import source opens %s %s more than once", identity.Name, identity.Version)
			}
			resolved, err := e.resolve(ctx, source)
			if err != nil {
				return nil, err
			}
			wanted[identity] = resolved.ID
		}
	}
	for _, source := range imported.Packages {
		metadata, err := readSourcePackage(source)
		if err != nil {
			return nil, err
		}
		identity := declaredPackage{Name: metadata.Name, Version: metadata.Version}
		known, asked := wanted[identity]
		if !asked {
			continue
		}
		resolved, err := e.resolve(ctx, source)
		if err != nil {
			return nil, err
		}
		if known != "" && known != resolved.ID {
			return nil, fmt.Errorf("invalid: the bootstrap import source stands on two different prepared sources named %s %s", identity.Name, identity.Version)
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

// bootstrapLandedFiles answers where in the importing stage this import put the marked
// files of its source. They are projected the way a binding is - by the directives of the
// copy, and only where the stage kept the bytes the copy landed - rather than guessed from
// where they ended up. For an import of a bootstrap image every file of the source is
// marked; for an import of an ordinary image the marks are the ones its own document
// publishes.
func bootstrapLandedFiles(ctx context.Context, imported SourceImport, marked map[string]bool, before, after *shippedscope.FileIndex) (map[string]bool, error) {
	asked := make(originalMatches, len(marked))
	for name := range marked {
		if _, exists := imported.Index.Files[name]; !exists {
			continue
		}
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

// markBootstrap takes on the obligation of the files an import of a bootstrap source
// landed, unless this image is a prepared source: such an image collects files and makes
// nothing, is answered for as the package it becomes, and so answers for them as a whole
// rather than one by one.
//
// The exemption reaches no further than that. An obligation this image inherited - from a
// base image, or from an import of an image that itself received such files - is another
// image's statement that those paths are unaccounted for, and a prepared source cannot
// discharge it by collecting them: those files still need a binding of their own here.
func (e *sourceEvidence) markBootstrap(landed, marks map[string]bool) {
	if e.preparedSource {
		return
	}
	maps.Copy(marks, landed)
}

// carryBootstrap keeps the obligation of a bootstrap source on the path the import landed
// it at, for as long as the build still holds a file there. The obligation is not what the
// bytes are but where they came from, so rewriting the file in place does not end it - a
// changed file then has to answer with its own build record or with the original its path
// is bound to, and with neither it is no-data. Deleting the path ends it: nothing of the
// bootstrap source is shipped any more.
//
// Bytes a stage copies to some other path are not followed. DK does not promise to track
// content a shell moved around, and marking every equal-byte file would refuse unrelated
// files that merely happen to be identical.
func (e *sourceEvidence) carryBootstrap(index *shippedscope.FileIndex) map[string]bool {
	return heldBootstrapMarks(e.bootstrap, index)
}
