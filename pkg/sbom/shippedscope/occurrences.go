package shippedscope

import (
	"maps"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"
)

// RecordOccurrences writes the files of each fileset onto the component that owns them, as
// evidence.occurrences: the path the file has in this image as location, and what is known
// of its content as additionalContext — the digest of a regular file, or symlinkContext
// for a symlink, which holds no bytes of its own. Every occurrence written here carries
// one or the other, so a reader can tell werf's own evidence from an occurrence that
// arrived in a merged document and means something else entirely.
//
// A component no fileset names is left as it was, and so is one whose complete filesets
// all declare no files at all. Nothing is then known about its files — its ecosystem records no file
// lists, it was installed in a way none of them reads, or it is a metapackage that ships
// nothing — and an empty occurrence list would instead claim its files were looked for and
// none were found. That is what keeps os-pm components unmarked when the image was
// installed by a pm too old to write a file list.
//
// Occurrences the component already carries are replaced: a fileset is what the image
// holds, and a scanner's guess at where it saw the package is not evidence of the same
// kind. The one exception is a fileset naming files the image holds at none of them, over
// a component werf itself recorded occurrences for before: those digests are the only way
// left to find the bytes where this image put them, and an empty list over them would say
// the files are gone when they may only have moved. Over a component werf never recorded,
// the empty list is written, because there is nothing else that could show the files and
// "its own file list names files it does not hold" is what an image that installed a
// package and then deleted it looks like.
//
// An incomplete manifest records unknown instead of treating its listed files as complete
// evidence. Existing occurrences are retained for provenance but ignored for the verdict.
// Unknown survives merging and later complete installs of the same component: those
// installs cannot establish completeness for an inherited origin.
//
// Returns the number of components whose file evidence was recorded or marked unknown.
func RecordOccurrences(bom *cdx.BOM, filesets []Fileset) int {
	if bom == nil || len(filesets) == 0 {
		return 0
	}

	owned := make(map[componentKey][]Fileset, len(filesets))
	for _, fileset := range filesets {
		key := componentKey{
			ecosystem: fileset.Ecosystem,
			name:      canonicalName(fileset.Ecosystem, fileset.Name),
			version:   fileset.Version,
		}
		owned[key] = append(owned[key], fileset)
	}

	recorded := 0
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok {
			return
		}

		sets, ok := owned[key]
		if !ok || !lo.SomeBy(sets, func(fileset Fileset) bool { return fileset.DeclaresFiles || fileset.Incomplete }) {
			return
		}

		if !setOccurrences(comp, sets) {
			return
		}
		recorded++
	})

	return recorded
}

// HasFileBackedComponents tells whether the BOM holds a component any ecosystem could
// record files for. Reading an image to find out costs a full download of its layers, and
// an image whose components are all Go modules, deb packages or anything else no collector
// reads has nothing to gain from it.
//
// Go and Rust are binary-backed, not file-backed: they need binary classification, not
// file enumeration.
func HasFileBackedComponents(bom *cdx.BOM) bool {
	if bom == nil {
		return false
	}

	found := false
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok {
			return
		}
		// Binary-backed ecosystems don't need file collection.
		if isBinaryBacked(key.ecosystem) {
			return
		}
		found = true
	})

	return found
}

// componentKey is what a fileset and a component have to agree on to be the same install:
// one ecosystem's idea of a package, not another's. Two ecosystems naming a package alike
// are two packages.
type componentKey struct {
	ecosystem Ecosystem
	name      string
	version   string
}

func keyOfComponent(comp *cdx.Component) (componentKey, bool) {
	if comp.PackageURL == "" {
		return componentKey{}, false
	}

	purl, err := packageurl.FromString(comp.PackageURL)
	if err != nil {
		return componentKey{}, false
	}

	ecosystem, ok := purlEcosystems[purl.Type]
	if !ok {
		return componentKey{}, false
	}

	name := purl.Name
	if purl.Namespace != "" {
		name = purl.Namespace + "/" + purl.Name
	}

	return componentKey{
		ecosystem: ecosystem,
		name:      canonicalName(ecosystem, name),
		version:   purl.Version,
	}, true
}

// purlEcosystems maps the purl type of a component to the ecosystem whose filesets can
// describe it. os-pm packages are pkg:generic, the type werf gives what its own pm
// installs; a deb or rpm component comes from a package manager whose file list nothing
// here reads, so it has no fileset and stays unmarked.
//
// pkg:generic is not werf's alone — syft gives it to a runtime it recognizes by its binary
// — but taking a fileset needs the same name and version as a package the pm recorded, and
// a component agreeing with a pm entry on both is that package.
//
// Go and Rust are binary-backed: they carry no files, only binaries that embed them.
var purlEcosystems = map[string]Ecosystem{
	packageurl.TypeGeneric: EcosystemOSPM,
	packageurl.TypePyPi:    EcosystemPython,
	packageurl.TypeNPM:     EcosystemJavaScript,
	luarocksPurlType:       EcosystemLua,
	packageurl.TypeGolang:  EcosystemGo,
	packageurl.TypeCargo:   EcosystemRust,
}

const luarocksPurlType = "luarocks"

// canonicalName spells a name the way its ecosystem considers canonical, so that a
// fileset and a component that mean the same package are keyed alike: PEP 503 folds
// separator runs and case, npm names are case-insensitive.
func canonicalName(ecosystem Ecosystem, name string) string {
	switch ecosystem {
	case EcosystemPython:
		return normalizePythonName(name)
	case EcosystemJavaScript:
		return strings.ToLower(name)
	default:
		return name
	}
}

// PropertyFiles records file evidence completeness. "none" preserves a checked-empty
// list across serialization; "unknown" means an origin's manifest could omit payload.
// Unknown survives merges even when another origin contributes a complete list.
const PropertyFiles = "werf:files"

// PropertyFilesNone is the value of that property stating, in so many words, that the
// component was checked and describes no files of the image.
const (
	PropertyFilesNone    = "none"
	propertyFilesUnknown = "unknown"
)

// symlinkContext marks an occurrence as a symlink, which has a path in the image but no
// content of its own to compare.
const symlinkContext = "symlink"

const digestPrefix = "sha256:"

// recordedOccurrences reads back what werf recorded of a component's files. An occurrence
// without a digest or the symlink marker came from somewhere else — a scanner noting where
// it saw a package, a document merged in — and says nothing about content; a component
// carrying none of werf's own is one nothing is known about, not one whose files were
// looked for and missed.
func recordedOccurrences(comp *cdx.Component) []Occurrence {
	if incompleteFileEvidence(comp) {
		return nil
	}
	if comp.Evidence == nil || comp.Evidence.Occurrences == nil {
		if propertyValue(comp, PropertyFiles) == PropertyFilesNone {
			return []Occurrence{}
		}

		return nil
	}

	recorded := *comp.Evidence.Occurrences
	occurrences := make([]Occurrence, 0, len(recorded))
	for _, occurrence := range recorded {
		switch {
		case occurrence.AdditionalContext == symlinkContext:
			occurrences = append(occurrences, Occurrence{Path: occurrence.Location, Symlink: true})
		case strings.HasPrefix(occurrence.AdditionalContext, digestPrefix):
			occurrences = append(occurrences, Occurrence{Path: occurrence.Location, Digest: occurrence.AdditionalContext})
		}
	}

	if len(recorded) > 0 && len(occurrences) == 0 && propertyValue(comp, PropertyFiles) != PropertyFilesNone {
		return nil
	}

	return occurrences
}

// setOccurrences records every file of every fileset of one component. npm installs a
// package more than once under different paths, and each copy is a fileset of its own;
// what the component ships is all of them. Reports whether anything was recorded.
func setOccurrences(comp *cdx.Component, sets []Fileset) bool {
	if incompleteFileEvidence(comp) || lo.SomeBy(sets, func(fileset Fileset) bool { return fileset.Incomplete }) {
		removeProperty(comp, PropertyFiles)
		setProperty(comp, PropertyFiles, propertyFilesUnknown)
		return true
	}

	contexts := make(map[string]string)
	for _, fileset := range sets {
		for file, entry := range fileset.Files {
			contexts[file] = entry.Digest
		}
		for link := range fileset.Symlinks {
			contexts[link] = symlinkContext
		}
	}

	if len(contexts) == 0 && recordedOccurrences(comp) != nil {
		return false
	}

	occurrences := make([]cdx.EvidenceOccurrence, 0, len(contexts))
	for _, file := range slices.Sorted(maps.Keys(contexts)) {
		occurrences = append(occurrences, cdx.EvidenceOccurrence{
			Location:          file,
			AdditionalContext: contexts[file],
		})
	}

	if comp.Evidence == nil {
		comp.Evidence = &cdx.Evidence{}
	}
	comp.Evidence.Occurrences = &occurrences

	if len(occurrences) == 0 {
		setProperty(comp, PropertyFiles, PropertyFilesNone)
	} else {
		removeProperty(comp, PropertyFiles)
	}

	return true
}

func incompleteFileEvidence(comp *cdx.Component) bool {
	return lo.SomeBy(lo.FromPtr(comp.Properties), func(property cdx.Property) bool {
		return property.Name == PropertyFiles && property.Value == propertyFilesUnknown
	})
}

func walkComponents(bom *cdx.BOM, visit func(comp *cdx.Component)) {
	var walk func(components []cdx.Component)
	walk = func(components []cdx.Component) {
		for i := range components {
			visit(&components[i])
			walk(lo.FromPtr(components[i].Components))
		}
	}

	walk(lo.FromPtr(bom.Components))
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		walk(lo.FromPtr(bom.Metadata.Component.Components))
	}
}
