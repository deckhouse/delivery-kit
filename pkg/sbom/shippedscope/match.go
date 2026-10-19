package shippedscope

import (
	"context"
	"path"
	"slices"

	"github.com/werf/logboek"
)

const (
	EcosystemGo   Ecosystem = "go"
	EcosystemRust Ecosystem = "rust"
)

// Occurrence is one file a component's SBOM says the component ships: the path it had in
// the image that recorded it, and the digest of its content there. Nothing says the file
// is still at that path, or still holds those bytes, in the image being matched.
type Occurrence struct {
	Path string
	// Digest is "sha256:<hex>". Empty for a symlink, which carries no bytes of its own.
	Digest  string
	Symlink bool
}

// Component is what the rule sees of one SBOM component. Occurrences nil means nothing is
// known about the component's files — an external image, an SBOM written before files
// were recorded — and the rule keeps it. Occurrences empty means its files were looked for
// and none were found, which is evidence like any other.
type Component struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	// Occurrences for a Go module is its import path alone; for a crate, its name and
	// version. Neither keeps a file of its own, so neither lists any.
	Occurrences []Occurrence
}

// ProducedBinaries is every binary the image's own build produced, classified. The rule
// takes the whole set rather than one binary at a time because a module is held by any
// binary that carries it, and only the union says which modules no binary does.
//
// A nil *ProducedBinaries means the produced set could not be established — an image
// built outside stapel — and every binary-backed component is kept. An empty one means
// the build produced nothing, which holds no module.
type ProducedBinaries struct {
	Binaries []BinaryClassification
}

type Reason string

const (
	// ReasonBinary — a produced binary names the component.
	ReasonBinary Reason = "binary"
	// ReasonContent — a file of the component is in the image, byte for byte, and no other
	// component of the same ecosystem claims those bytes.
	ReasonContent Reason = "content"
	// ReasonContentShared — the component's files in the image are all shared with other
	// components of its ecosystem, and none of those proved itself present either.
	ReasonContentShared Reason = "content-shared"
	// ReasonPath — a path of the component exists in the image with other bytes, and no
	// proven component explains that path.
	ReasonPath Reason = "path"
	// ReasonName — a file named like one of the component's exists somewhere in the image,
	// unexplained, and no other component has a file of that name.
	ReasonName Reason = "name"
	// ReasonNoData — nothing is known about the component's files.
	ReasonNoData Reason = "no-data"
	// ReasonFailOpen — a produced binary could carry the component but names nothing.
	ReasonFailOpen Reason = "fail-open"
	// ReasonNotLinked — no produced binary carries the component.
	ReasonNotLinked Reason = "not-linked"
	// ReasonNoMatch — none of the component's files, paths or names are in the image.
	ReasonNoMatch Reason = "no-match"
)

// Decision says whether one component shipped in the image, and why.
type Decision struct {
	Shipped bool
	Reason  Reason
	// Checked counts the occurrences the rule compared against the image; zero when the
	// decision did not rest on them.
	Checked int
	// Matched holds the image paths that proved the component present, so a consumer can
	// record where the component is in this image rather than where it was in the donor.
	Matched []string
}

// Match decides, for every component, whether the image ships it. Verdicts come back in
// the order of components.
//
// A component is dropped only when every check misses. Checks run from strongest to
// weakest, each one there for the case the previous was defeated by a deliberate change to
// a file — strip, patchelf, a certificate bundle regenerated after install:
//
//  1. A Go module or a crate is held by any produced binary that names it. One binary
//     legitimately names many, so no exclusivity applies. A binary that could carry
//     components but names none holds all of them.
//  2. A file-backed component is held by a file of its own in the image, byte for byte —
//     provided no other component of the same ecosystem claims the same bytes, counted by
//     (name, version) so that identical copies of one package are one owner. A component
//     whose every matching file is shared is held only when none of the co-owners proved
//     itself by a file of its own: the one physical file belongs to whoever did.
//  3. Among files no proven component explains: a component's path still present in the
//     image holds it; failing that, a file named like one of its, when no other component
//     has a file of that name and the name is not one every package carries.
//
// A zero-size file proves nothing — its digest is the same for every package.
func Match(ctx context.Context, components []Component, binaries *ProducedBinaries, index *FileIndex) []Decision {
	decisions := make([]Decision, len(components))

	evidence := collectBinaryEvidence(binaries)
	owners := collectOwners(components)
	names := collectNames(components)
	byDigest := indexByDigest(index)

	// A path the rule has already credited to some component. Symlinks of proven
	// components count too: a symlink carries no bytes and would otherwise hold a stale
	// version through its path.
	explained := make(map[string]bool)
	type sharedHit struct {
		component int
		digest    string
		path      string
	}
	var shared []sharedHit
	contentKept := make(map[owner]bool)

	for i, component := range components {
		switch component.Ecosystem {
		case EcosystemGo:
			decisions[i] = evidence.goVerdict(component)

			continue
		case EcosystemRust:
			decisions[i] = evidence.rustVerdict(component)

			continue
		}

		if component.Occurrences == nil {
			decisions[i] = Decision{Shipped: true, Reason: ReasonNoData}

			continue
		}

		decision := Decision{Checked: len(component.Occurrences)}
		for _, occurrence := range component.Occurrences {
			if occurrence.Symlink || occurrence.Digest == "" {
				continue
			}

			for _, imagePath := range byDigest[occurrence.Digest] {
				explained[imagePath] = true

				if len(owners[ownerKey{component.Ecosystem, occurrence.Digest}]) > 1 {
					shared = append(shared, sharedHit{component: i, digest: occurrence.Digest, path: imagePath})

					continue
				}

				decision.Shipped = true
				decision.Reason = ReasonContent
				decision.Matched = append(decision.Matched, imagePath)
			}
		}

		if decision.Shipped {
			contentKept[ownerOf(component)] = true
			for _, occurrence := range component.Occurrences {
				if occurrence.Symlink {
					explained[occurrence.Path] = true
				}
			}
		}

		decisions[i] = decision
	}

	for _, hit := range shared {
		if decisions[hit.component].Shipped {
			continue
		}

		component := components[hit.component]
		if slices.ContainsFunc(owners[ownerKey{component.Ecosystem, hit.digest}], func(other owner) bool {
			return other != ownerOf(component) && contentKept[other]
		}) {
			continue
		}

		decisions[hit.component].Shipped = true
		decisions[hit.component].Reason = ReasonContentShared
		decisions[hit.component].Matched = append(decisions[hit.component].Matched, hit.path)
	}

	for i, component := range components {
		if decisions[i].Shipped || isBinaryBacked(component.Ecosystem) || component.Occurrences == nil {
			continue
		}

		decision := &decisions[i]
		for _, occurrence := range component.Occurrences {
			if explained[occurrence.Path] {
				continue
			}
			if _, ok := index.Files[occurrence.Path]; !ok {
				if _, ok := index.Symlinks[occurrence.Path]; !ok {
					continue
				}
			}

			decision.Shipped = true
			decision.Reason = ReasonPath
			decision.Matched = append(decision.Matched, occurrence.Path)
		}
		if decision.Shipped {
			continue
		}

		for _, occurrence := range component.Occurrences {
			name := path.Base(occurrence.Path)
			if isGenericName(name) || len(names[name]) > 1 {
				continue
			}

			for imagePath := range index.Files {
				if explained[imagePath] || path.Base(imagePath) != name {
					continue
				}

				decision.Shipped = true
				decision.Reason = ReasonName
				decision.Matched = append(decision.Matched, imagePath)
			}
			for imagePath := range index.Symlinks {
				if explained[imagePath] || path.Base(imagePath) != name {
					continue
				}

				decision.Shipped = true
				decision.Reason = ReasonName
				decision.Matched = append(decision.Matched, imagePath)
			}
		}
		if decision.Shipped {
			continue
		}

		decision.Reason = ReasonNoMatch
		logboek.Context(ctx).Debug().LogF("not shipped %s %s@%s: checked %d files, 0 matches\n",
			component.Ecosystem, component.Name, component.Version, decision.Checked)
	}

	for i := range decisions {
		slices.Sort(decisions[i].Matched)
		decisions[i].Matched = slices.Compact(decisions[i].Matched)
	}

	return decisions
}

// indexByDigest inverts the index for the content pass, leaving out zero-size files: their
// digest is the same for every package and proves nothing.
func indexByDigest(index *FileIndex) map[string][]string {
	byDigest := make(map[string][]string)
	for imagePath, file := range index.Files {
		if file.Size == 0 {
			continue
		}

		byDigest[file.Digest] = append(byDigest[file.Digest], imagePath)
	}
	for _, paths := range byDigest {
		slices.Sort(paths)
	}

	return byDigest
}

func isBinaryBacked(ecosystem Ecosystem) bool {
	return ecosystem == EcosystemGo || ecosystem == EcosystemRust
}

type binaryEvidence struct {
	known bool

	goFailOpen bool
	modules    map[string]bool

	rustFailOpen bool
	crates       map[Crate]bool
}

func collectBinaryEvidence(binaries *ProducedBinaries) binaryEvidence {
	evidence := binaryEvidence{
		modules: make(map[string]bool),
		crates:  make(map[Crate]bool),
	}
	if binaries == nil {
		return evidence
	}
	evidence.known = true

	for _, binary := range binaries.Binaries {
		if binary.TestBinary {
			continue
		}

		switch binary.Go {
		case VerdictUnknown:
			evidence.goFailOpen = true
		case VerdictNames:
			for _, module := range binary.Modules {
				evidence.modules[module] = true
			}
		}

		switch binary.Rust {
		case VerdictUnknown:
			evidence.rustFailOpen = true
		case VerdictNames:
			for _, crate := range binary.Crates {
				evidence.crates[crate] = true
			}
		}
	}

	return evidence
}

func (e binaryEvidence) goVerdict(component Component) Decision {
	switch {
	case !e.known:
		return Decision{Shipped: true, Reason: ReasonNoData}
	case e.goFailOpen:
		return Decision{Shipped: true, Reason: ReasonFailOpen}
	case e.modules[component.Name]:
		return Decision{Shipped: true, Reason: ReasonBinary}
	}

	return Decision{Reason: ReasonNotLinked}
}

func (e binaryEvidence) rustVerdict(component Component) Decision {
	switch {
	case !e.known:
		return Decision{Shipped: true, Reason: ReasonNoData}
	case e.rustFailOpen:
		return Decision{Shipped: true, Reason: ReasonFailOpen}
	case e.crates[Crate{Name: component.Name, Version: component.Version}]:
		return Decision{Shipped: true, Reason: ReasonBinary}
	}

	return Decision{Reason: ReasonNotLinked}
}

// owner is a component as the exclusivity count sees it: one package version, however
// many copies of it the image holds.
type owner struct {
	ecosystem Ecosystem
	name      string
	version   string
}

func ownerOf(component Component) owner {
	return owner{component.Ecosystem, component.Name, component.Version}
}

type ownerKey struct {
	ecosystem Ecosystem
	digest    string
}

// collectOwners answers, for every digest a file-backed component claims, which owners of
// its own ecosystem claim it. The ecosystem is part of the key because ownership across
// ecosystems is hierarchical, not competing: a deb package that ships an npm tree and the
// npm packages in that tree both legitimately own the same files.
func collectOwners(components []Component) map[ownerKey][]owner {
	owners := make(map[ownerKey][]owner)
	for _, component := range components {
		if isBinaryBacked(component.Ecosystem) {
			continue
		}

		for _, occurrence := range component.Occurrences {
			if occurrence.Symlink || occurrence.Digest == "" {
				continue
			}

			key := ownerKey{component.Ecosystem, occurrence.Digest}
			if !slices.Contains(owners[key], ownerOf(component)) {
				owners[key] = append(owners[key], ownerOf(component))
			}
		}
	}

	return owners
}

func collectNames(components []Component) map[string][]owner {
	names := make(map[string][]owner)
	for _, component := range components {
		if isBinaryBacked(component.Ecosystem) {
			continue
		}

		for _, occurrence := range component.Occurrences {
			name := path.Base(occurrence.Path)
			if !slices.Contains(names[name], ownerOf(component)) {
				names[name] = append(names[name], ownerOf(component))
			}
		}
	}

	return names
}

// isGenericName names the files nearly every package carries, so that one of them in the
// image says nothing about which package it came with.
func isGenericName(name string) bool {
	switch name {
	case "LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.LIB", "NOTICE",
		"README", "README.md", "README.txt", "README.rst", "CHANGELOG", "CHANGELOG.md", "changelog",
		"changelog.gz", "changelog.Debian.gz", "copyright", "AUTHORS", "CONTRIBUTING.md",
		"package.json", "RECORD", "METADATA", "WHEEL", "INSTALLER", "top_level.txt", "__init__.py",
		"index.js", "index.d.ts", "setup.py", "Makefile", ".gitignore", ".npmignore":
		return true
	}

	return false
}
