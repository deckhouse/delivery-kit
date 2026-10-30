package shippedscope

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/logboek"
)

// DropReplacedOccurrences strikes out of an inherited document every whereabouts this
// image does not bear out: a path the base stated its component stands at that the image
// does not hold at all, and one the image holds with other bytes than the base recorded
// there. A descendant replaces a file of its base - a certificate bundle the package
// owning it regenerates - and the base's occurrence then states a digest of content this
// image does not carry anywhere, which is a claim about files rather than a record of
// them.
//
// A component every occurrence of which goes this way had its files looked for and none of
// them found, which is the same thing the package database says of a package it does not
// record: the image does not ship it. One that keeps a path keeps its verdict too; the
// file that was replaced was never the whole of it.
//
// This asks of a path what stands there, which is narrower than asking whether the bytes
// are anywhere in the image: a file of a base package the build moved elsewhere is dropped
// here, where the content tier of the shipped-scope rule would have found it. What a base
// states is where its own files stood, and a path of this image holding other content, or
// nothing, is the image contradicting that statement rather than relocating it.
//
// An occurrence stating no digest - a path a package database named, a scanner's note -
// says nothing of content and is held to presence alone. An occurrence standing in a
// package manager's own bookkeeping is not judged at all: a build that strips the docs or
// the database entries of its base says nothing about the files that package ships, and
// a component stating nothing but such paths is left exactly as it arrived.
//
// A component already judged not shipped is left as it is: that verdict is about this
// image already, and nothing here would add to it. So is one whose file evidence is
// declared incomplete, whose occurrences are provenance rather than a list of what it
// ships.
//
// Paths are read the way the image resolves them: a base that merged /lib into /usr/lib
// has its files named under both spellings - the database's and the image's - and both
// name the same file.
//
// It is given the base document alone, before anything is merged into it. The verified
// composition of this image is read out of the image itself, and what an import directive
// brought in states the paths of the donor's image, which the import has yet to project
// onto this one - a path of this image's own tree is not what those occurrences name.
//
// An index that did not read whole settles nothing: a path missing from it is one that was
// not proven present rather than one proven absent, and its digests at a path a hardlink
// reaches are the final filesystem's rather than the layer's.
//
// Reports how many occurrences were dropped and how many components were marked as not
// shipped.
func DropReplacedOccurrences(ctx context.Context, bom *cdx.BOM, index *FileIndex) (int, int) {
	if bom == nil || index == nil || index.Incomplete {
		return 0, 0
	}

	dropped, marked := 0, 0
	walkComponents(bom, func(comp *cdx.Component) {
		if propertyValue(comp, PropertyShipped) == PropertyShippedFalse || incompleteFileEvidence(comp) {
			return
		}

		occurrences := lo.FromPtr(lo.FromPtr(comp.Evidence).Occurrences)
		held := 0
		kept := make([]cdx.EvidenceOccurrence, 0, len(occurrences))
		for _, occurrence := range occurrences {
			judged, borneOut := judgeOccurrence(occurrence, index)
			switch {
			case !judged:
			case borneOut:
				held++
			default:
				dropped++
				logboek.Context(ctx).Debug().LogF("inherited occurrence %s of %s %s is not what the image holds there\n", occurrence.Location, comp.Name, comp.Version)

				continue
			}
			kept = append(kept, occurrence)
		}
		if len(kept) == len(occurrences) {
			return
		}

		comp.Evidence.Occurrences = &kept
		if held > 0 {
			return
		}

		setProperty(comp, PropertyShipped, PropertyShippedFalse)
		marked++
		logboek.Context(ctx).Debug().LogF("inherited package %s %s stands at none of the paths its base recorded for it\n", comp.Name, comp.Version)
	})

	return dropped, marked
}

// judgeOccurrence answers whether this occurrence is one the image can be held to, and
// whether the image bears it out: the content, where a digest names it, and the path
// otherwise. The path is read as the image resolves it, through the symlinks of the
// directories above it, so that both spellings of a merged /lib reach the one file.
func judgeOccurrence(occurrence cdx.EvidenceOccurrence, index *FileIndex) (bool, bool) {
	if occurrence.Location == "" {
		return false, false
	}
	stated := rootedPath(occurrence.Location)
	if packageMetadataPath(stated) {
		return false, false
	}
	file := resolveDirSymlinks(index, stated)

	evidence, recorded := occurrenceEvidence(occurrence)
	if recorded && evidence.Digest != "" {
		entry, held := index.Files[file]

		return true, held && entry.Digest == evidence.Digest
	}

	return true, heldAtPath(index, file)
}

func heldAtPath(index *FileIndex, file string) bool {
	if _, held := index.Files[file]; held {
		return true
	}
	if _, held := index.Symlinks[file]; held {
		return true
	}
	_, held := index.Directories[file]

	return held
}

// packageMetadataLocations are the trees a package manager keeps its own bookkeeping in,
// and the one a distribution keeps the documentation of its packages in. What a build did
// to a file there - a database entry rewritten by a later install, a docs tree stripped to
// make the image smaller - is not the package's payload and says nothing about whether the
// image ships it.
var packageMetadataLocations = []string{
	"/var/lib/dpkg",
	"/var/lib/rpm",
	"/usr/lib/sysimage/rpm",
	"/lib/apk/db",
	"/usr/share/doc",
}

func packageMetadataPath(file string) bool {
	return lo.SomeBy(packageMetadataLocations, func(dir string) bool {
		return file == dir || hasPathPrefix(file, dir)
	})
}
