package shippedscope

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// HasDistroPackageComponents answers whether a document claims any package of a
// distribution at all, which is the only reason to decide its claims again.
func HasDistroPackageComponents(bom *cdx.BOM) bool {
	if bom == nil {
		return false
	}
	found := false
	walkComponents(bom, func(comp *cdx.Component) {
		found = found || distroPackageComponent(comp)
	})

	return found
}

// RecomputeDonorPackages decides afresh, from the package database of the image an import
// copies from, what that image's own SBOM says about its distribution packages.
//
// The document of an import source is somebody else's statement. Where it came from a
// supplier, the packages in it are the supplier's claim and so is everything said beside
// them: that a package is not shipped, that it describes no files, that it is excluded
// from the document, or where its files stand. An image that took any of that on trust
// could be told by a supplier's SBOM that a package the supplier ships is not shipped -
// hiding it from this image and from everything downstream of it - or be handed paths
// nothing checked. The donor image is read here anyway, for the snapshots the verification
// works from, and its own database answers all of it first-hand.
//
// So every such statement is cleared and the question reached again: a package the database
// records is placed at the files the donor holds, which the import scope then projects onto
// what this image received; one the database does not record is marked as not shipped, by
// this build rather than on anybody's word; and where there is no database to read, or no
// file list in it, nothing is concluded and the component ends up placed nowhere - a
// partial import of it yields no data, which is the answer when nobody can say where a
// thing stands.
//
// Only the packages of a distribution are touched. Every other component of the donor's
// document is its own affair, decided by the passes that own those ecosystems.
//
// Reports how many components were placed and how many were marked absent.
func RecomputeDonorPackages(ctx context.Context, bom *cdx.BOM, database *DistroDatabase) (int, int) {
	if bom == nil {
		return 0, 0
	}

	walkComponents(bom, func(comp *cdx.Component) {
		if !distroPackageComponent(comp) {
			return
		}
		// Each of these is the donor's verdict in a different spelling, and what
		// this build is about to decide, it decides from the donor's database or
		// not at all.
		removeProperty(comp, PropertyShipped)
		removeProperty(comp, PropertyFiles)
		if comp.Scope == cdx.ScopeExcluded {
			comp.Scope = ""
		}
		// The paths too: a document may name any path it likes, and one nothing
		// checked would decide what this image is said to have received.
		if comp.Evidence != nil {
			comp.Evidence.Occurrences = nil
		}
	})

	return PlaceInheritedPackages(ctx, bom, database)
}
