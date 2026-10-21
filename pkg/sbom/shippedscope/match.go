package shippedscope

import (
	"context"
	"path"
	"slices"

	"github.com/samber/lo"

	"github.com/werf/logboek"
)

const (
	EcosystemGo   Ecosystem = "go"
	EcosystemRust Ecosystem = "rust"
)

// Occurrence is one file a component's SBOM says the component ships: the path it has in
// the image being matched, and the digest its content had in the image that recorded it.
// Nothing says the file is still at that path, or still holds those bytes.
//
// The path is the caller's to relocate: an occurrence recorded in a donor under
// `/usr/bin/jq` and imported with `to: /bin` arrives here as `/bin/jq`. The rule compares
// paths verbatim and knows nothing of imports, so a donor path passed unrelocated makes
// the path tier miss silently while the content tier still matches.
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
	// For Go and Rust, occurrences must identify binaries previously classified as
	// carrying this module or crate. The caller must exclude manifests and source files;
	// a matching digest alone cannot establish that a binary contains the dependency.
	Occurrences []Occurrence
}

// ProducedBinaries is every binary the image's own build produced, classified. The rule
// takes the whole set rather than one binary at a time because a module is held by any
// binary that carries it, and only the union says which modules no binary does.
//
// Known false means the produced set could not be established — an image built outside
// stapel — and every binary-backed component is kept. Known true with no binaries means
// the build produced nothing, which holds no module.
//
// A binary imported from another image is not produced here and does not belong in this
// set: the modules it carries are the donor's SBOM's to prove, and arrive as components
// with their own evidence. Putting it here would hold the donor's modules in an image
// that merely copied the file.
type ProducedBinaries struct {
	Known    bool
	Binaries []BinaryClassification
}

type Reason string

const (
	// ReasonBinary — a produced binary names the component.
	ReasonBinary Reason = "binary"
	// ReasonBinaryInherited — a binary this image did not build, but carries byte for
	// byte, was recorded as naming the component by the image that did build it.
	ReasonBinaryInherited Reason = "binary-inherited"
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
	// Checked counts the files whose bytes the rule looked for in the image; symlinks
	// carry none and are not counted. Zero when the decision did not rest on files.
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
//     components but names none holds all of them. Failing that, it is held by a binary
//     the image carries byte for byte that the image which built it recorded as naming
//     the component: an imported binary is none of this image's business to classify,
//     and the donor already did.
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
//
// Two files with the same bytes at two paths are two files. A component's own path in the
// image is contested only by the components that declare that path; the bytes it shares
// with a file elsewhere are not a claim on that file. Only when nobody declares the image
// path — the file was moved on its way in — do all owners of the bytes contest it.
//
// Binary-backed and file-backed components do not see each other: a produced Go binary is
// a file in the image like any other and can hold an unrelated file-backed component of
// the same name through the name tier, which is the holding direction.
func Match(ctx context.Context, components []Component, binaries ProducedBinaries, index *FileIndex) []Decision {
	if index == nil {
		panic("shippedscope.Match: index is nil")
	}

	decisions := make([]Decision, len(components))

	evidence := collectBinaryEvidence(binaries)
	owners, ownersAtPath := collectOwners(components)
	names := collectNames(components)
	byDigest := indexByDigest(index)
	byName := indexByName(index)

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
			decisions[i] = holdByInheritedBinary(evidence.goVerdict(component), component, byDigest)

			continue
		case EcosystemRust:
			decisions[i] = holdByInheritedBinary(evidence.rustVerdict(component), component, byDigest)

			continue
		}

		if component.Occurrences == nil {
			decisions[i] = Decision{Shipped: true, Reason: ReasonNoData}

			continue
		}

		decision := Decision{}
		for _, occurrence := range component.Occurrences {
			if occurrence.Symlink || occurrence.Digest == "" {
				continue
			}
			decision.Checked++

			for _, imagePath := range byDigest[occurrence.Digest] {
				explained[imagePath] = true

				contestants := ownersAtPath[ownerPathKey{component.Ecosystem, occurrence.Digest, imagePath}]
				if len(contestants) == 0 {
					contestants = owners[ownerKey{component.Ecosystem, occurrence.Digest}]
				}
				if !lo.Contains(contestants, ownerOf(component)) {
					// Someone else declares this path with these bytes; the component's own
					// claim is on another path, present or not.
					continue
				}

				if len(contestants) > 1 {
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
		component := components[hit.component]
		decision := &decisions[hit.component]

		contestants := ownersAtPath[ownerPathKey{component.Ecosystem, hit.digest, hit.path}]
		if len(contestants) == 0 {
			contestants = owners[ownerKey{component.Ecosystem, hit.digest}]
		}
		provenElsewhere := lo.ContainsBy(contestants, func(other owner) bool {
			return other != ownerOf(component) && contentKept[other]
		})

		switch {
		case decision.Reason == ReasonContent:
			// A proven owner is credited with its shared files too: the rule has decided
			// they are its, and a consumer rewriting occurrences from Matched would
			// otherwise lose them for the next image in the chain.
			decision.Matched = append(decision.Matched, hit.path)
		case provenElsewhere:
			continue
		default:
			decision.Shipped = true
			decision.Reason = ReasonContentShared
			decision.Matched = append(decision.Matched, hit.path)
		}
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

			for _, imagePath := range byName[name] {
				if explained[imagePath] {
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

func indexByName(index *FileIndex) map[string][]string {
	byName := make(map[string][]string)
	for imagePath := range index.Files {
		byName[path.Base(imagePath)] = append(byName[path.Base(imagePath)], imagePath)
	}
	for imagePath := range index.Symlinks {
		byName[path.Base(imagePath)] = append(byName[path.Base(imagePath)], imagePath)
	}
	for _, paths := range byName {
		slices.Sort(paths)
	}

	return byName
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

func collectBinaryEvidence(binaries ProducedBinaries) binaryEvidence {
	evidence := binaryEvidence{
		known:   binaries.Known,
		modules: make(map[string]bool),
		crates:  make(map[Crate]bool),
	}

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

// holdByInheritedBinary keeps a component the produced set does not account for when a
// binary recorded as carrying it is in the image byte for byte. The produced set is
// deliberately the image's own binaries, so an imported one is absent from it and would
// otherwise read as "no binary carries this" — the donor's SBOM is what says otherwise,
// and it travels with the component as its occurrences.
func holdByInheritedBinary(verdict Decision, component Component, byDigest map[string][]string) Decision {
	if verdict.Shipped {
		return verdict
	}

	for _, occurrence := range component.Occurrences {
		if occurrence.Digest == "" {
			continue
		}

		for _, imagePath := range byDigest[occurrence.Digest] {
			verdict.Shipped = true
			verdict.Reason = ReasonBinaryInherited
			verdict.Matched = append(verdict.Matched, imagePath)
		}
	}

	return verdict
}

func (e binaryEvidence) goVerdict(component Component) Decision {
	switch {
	case !e.known:
		return Decision{Shipped: true, Reason: ReasonNoData}
	case e.modules[component.Name]:
		return Decision{Shipped: true, Reason: ReasonBinary}
	case e.goFailOpen:
		return Decision{Shipped: true, Reason: ReasonFailOpen}
	}

	return Decision{Reason: ReasonNotLinked}
}

func (e binaryEvidence) rustVerdict(component Component) Decision {
	switch {
	case !e.known:
		return Decision{Shipped: true, Reason: ReasonNoData}
	case e.crates[Crate{Name: component.Name, Version: component.Version}]:
		return Decision{Shipped: true, Reason: ReasonBinary}
	case e.rustFailOpen:
		return Decision{Shipped: true, Reason: ReasonFailOpen}
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

type ownerPathKey struct {
	ecosystem Ecosystem
	digest    string
	path      string
}

// collectOwners answers, for every digest a file-backed component claims, which owners of
// its own ecosystem claim it — in all, and at each declared path. The ecosystem is part of
// the key because ownership across ecosystems is hierarchical, not competing: a deb
// package that ships an npm tree and the npm packages in that tree both legitimately own
// the same files.
func collectOwners(components []Component) (map[ownerKey][]owner, map[ownerPathKey][]owner) {
	owners := make(map[ownerKey][]owner)
	ownersAtPath := make(map[ownerPathKey][]owner)
	for _, component := range components {
		if isBinaryBacked(component.Ecosystem) {
			continue
		}

		for _, occurrence := range component.Occurrences {
			if occurrence.Symlink || occurrence.Digest == "" {
				continue
			}

			key := ownerKey{component.Ecosystem, occurrence.Digest}
			if !lo.Contains(owners[key], ownerOf(component)) {
				owners[key] = append(owners[key], ownerOf(component))
			}
			pathKey := ownerPathKey{component.Ecosystem, occurrence.Digest, occurrence.Path}
			if !lo.Contains(ownersAtPath[pathKey], ownerOf(component)) {
				ownersAtPath[pathKey] = append(ownersAtPath[pathKey], ownerOf(component))
			}
		}
	}

	return owners, ownersAtPath
}

// collectNames answers which owners declare a file of each basename. Unlike content
// ownership this is counted across ecosystems: a name is the weakest evidence, and a file
// two components of any kind could have left there says nothing about which one did.
func collectNames(components []Component) map[string][]owner {
	names := make(map[string][]owner)
	for _, component := range components {
		if isBinaryBacked(component.Ecosystem) {
			continue
		}

		for _, occurrence := range component.Occurrences {
			name := path.Base(occurrence.Path)
			if !lo.Contains(names[name], ownerOf(component)) {
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
