package shippedscope

import (
	"context"
	"maps"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/werf/logboek"
)

// distroPurlTypes are the package managers whose packages belong to the image's own
// distribution, and whose file lists a distribution keeps rather than this project.
var distroPurlTypes = map[string]struct{}{"deb": {}, "rpm": {}, "apk": {}}

// distroPackageComponent answers whether this component is a package of a distribution,
// whichever of them keeps it.
func distroPackageComponent(comp *cdx.Component) bool {
	if comp.PackageURL == "" {
		return false
	}
	purl, err := packageurl.FromString(comp.PackageURL)
	if err != nil {
		return false
	}
	_, ok := distroPurlTypes[purl.Type]

	return ok
}

// dpkgPurlType is the one package manager whose database this reads. A component of
// another manager is left exactly as it arrived: an rpm package is not absent from an
// image because the image's dpkg database does not mention it, and saying so would be a
// statement about a database nobody opened.
const dpkgPurlType = "deb"

// PlaceInheritedPackages gives the package components an image inherited from its base's
// SBOM the whereabouts the image's own package database records for them.
//
// A supplier states the packages of its image and, as a rule, not the files of each. Those
// components travel into this project's document pathless, and an image importing a part of
// such an image can place none of them. The database the image itself carries says where
// they stand, and reading it is the only way to tell a package the import carried from one
// it left behind.
//
// It is given the base document alone, before anything is merged into it. What an import
// brought in came out of another image, whose packages this image's database knows nothing
// about and whose paths it would name wrongly.
//
// A package the database records at the name, version and architecture the component
// claims is placed at the files it holds. One whose name the database knows at some other
// version or architecture, or does not know at all, is marked as not shipped: dpkg keeps
// one installed version of a name per architecture, so another version of it is not in
// this image. One the database records with no file list of its own is left pathless,
// which says where it stands and not whether it ships anything.
//
// Nothing at all is concluded where the image carries no database this reads. Its silence
// is not a statement that the packages of its base are absent; it is the absence of a
// statement.
//
// It touches nothing else. A component the scan already placed keeps its occurrences, one
// already judged keeps that judgement, and a component of any other ecosystem - or of a
// package manager whose database this does not read - is left to the pass that owns it.
// The paths settle scope and nothing more: what the package is made of stays the
// supplier's claim, and a compiled file still answers with its own record.
//
// Reports how many components were placed and how many were marked absent.
func PlaceInheritedPackages(ctx context.Context, bom *cdx.BOM, database *DistroDatabase) (int, int) {
	if bom == nil || database == nil || !database.Present {
		return 0, 0
	}
	known := make(map[string]bool, len(database.Packages))
	for _, entry := range database.Packages {
		known[entry.Name] = true
	}

	placed, absent := 0, 0
	walkComponents(bom, func(comp *cdx.Component) {
		purl, ok := inheritedDistroPurl(comp)
		if !ok {
			return
		}
		entry, installed := database.Packages[DistroPackageKey(purl.Name, purl.Version, purl.Qualifiers.Map()["arch"])]
		switch {
		case installed && entry.DeclaresFiles:
			if setOccurrences(comp, []Fileset{{
				Ecosystem: EcosystemOSPM, Name: entry.Name, Version: entry.Version,
				Files: entry.Files, Symlinks: entry.Symlinks, DeclaresFiles: true,
			}}) {
				placed++
			}
		case installed:
			// Installed, and the database recorded no files for it. Nothing here
			// can say where it stands, and saying it ships nothing would be a
			// different claim entirely.
		case !known[purl.Name]:
			// The database of the image is the authority on what dpkg installed
			// in it, and it has never heard of this one.
			setProperty(comp, PropertyShipped, PropertyShippedFalse)
			absent++
			logboek.Context(ctx).Debug().LogF("inherited package %s %s is not in the package database of the image\n", purl.Name, purl.Version)
		case purl.Qualifiers.Map()["arch"] != "":
			// The name is installed, at another version or for another
			// architecture. Either way, not this package.
			setProperty(comp, PropertyShipped, PropertyShippedFalse)
			absent++
			logboek.Context(ctx).Debug().LogF("inherited package %s is in the package database of the image at another version than %s\n", purl.Name, purl.Version)
		default:
			// The name is installed and the component says nothing of which
			// architecture it means, so which entry it is talking about, if any,
			// is not settled here.
			logboek.Context(ctx).Debug().LogF("inherited package %s %s names no architecture, and the package database records that name for another one\n", purl.Name, purl.Version)
		}
	})

	return placed, absent
}

// inheritedDistroPurl answers whether this component is a supplier's package statement that
// nothing has placed or judged yet.
func inheritedDistroPurl(comp *cdx.Component) (packageurl.PackageURL, bool) {
	if comp.PackageURL == "" || statesOccurrences(comp) {
		return packageurl.PackageURL{}, false
	}
	// A component the ordinary pass already decided about is not revisited: whatever it
	// read, it read from this same image.
	if propertyValue(comp, PropertyShipped) != "" || propertyValue(comp, PropertyFiles) != "" {
		return packageurl.PackageURL{}, false
	}
	purl, err := packageurl.FromString(comp.PackageURL)
	if err != nil || purl.Type != dpkgPurlType || purl.Name == "" || purl.Version == "" {
		return packageurl.PackageURL{}, false
	}

	return purl, true
}

func statesOccurrences(comp *cdx.Component) bool {
	return lo.SomeBy(lo.FromPtr(lo.FromPtr(comp.Evidence).Occurrences), func(occurrence cdx.EvidenceOccurrence) bool {
		return occurrence.Location != ""
	})
}

// InheritedPackagePaths is what the placed components were given, for a caller that wants
// to report it. Kept sorted so that a build of the same image reports the same thing.
func InheritedPackagePaths(entry DistroPackage) []string {
	return slices.Sorted(maps.Keys(entry.Files))
}
