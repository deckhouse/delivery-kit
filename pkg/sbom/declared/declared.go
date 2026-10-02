// Package declared records which packages of an image its werf.yaml declares.
//
// A packages directive names the packages a project asks for: the `require` of
// a go.mod, the dependencies of a package.json, the spec of an os-pm entry. The
// SBOM lists far more — everything those packages pull in. CycloneDX has a
// place for the distinction: a `dependsOn` edge from the root component of the
// BOM (metadata.component, the image) to a component says the image itself
// uses that component. This package parses the declaration out of the spec
// file a directive points at, finds the components it names and emits that
// edge. The GOST attack surface is then split along it: what the root depends
// on is directly reachable, everything else is pulled in indirectly.
//
// A declaration is matched to a component by purl type and name; the version
// takes part only when the declaration pins one exactly, since most manifests
// carry ranges. A declaration no component matches is not an error — the
// manager may have skipped it, or syft may have failed to catalog it — and is
// ignored.
package declared

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/config"
)

// Package is one declared package. Version is empty unless the declaration pins
// an exact one.
type Package struct {
	Name    string
	Version string
}

// ParseSpec extracts the declared packages of a directive from its spec file.
// For os-pm, which has no spec file, use FromOSPMSpec.
func ParseSpec(ecosystem config.PackagesDirectiveType, spec []byte) ([]Package, error) {
	switch ecosystem {
	case config.PackagesDirectiveTypeGoMod:
		return parseGoMod(spec)
	case config.PackagesDirectiveTypeJavaScriptNpm, config.PackagesDirectiveTypeJavaScriptYarn, config.PackagesDirectiveTypeJavaScriptPnpm:
		return parsePackageJSON(spec)
	case config.PackagesDirectiveTypeRustCargo:
		return parseCargoToml(spec)
	case config.PackagesDirectiveTypePythonPoetry, config.PackagesDirectiveTypePythonUV:
		return parsePyprojectToml(spec)
	case config.PackagesDirectiveTypePythonPip:
		return parseRequirementsTxt(spec)
	case config.PackagesDirectiveTypeLuaRock:
		return parseRockspec(spec)
	default:
		return nil, fmt.Errorf("packages type %q has no spec file to declare packages from", ecosystem)
	}
}

// FromOSPMSpec reads the `name==version` entries of an os-pm directive spec.
// An entry without `==` declares the package by name only.
func FromOSPMSpec(spec []string) []Package {
	pkgs := make([]Package, 0, len(spec))
	for _, entry := range spec {
		name, version, _ := strings.Cut(strings.TrimSpace(entry), "==")
		if name == "" {
			continue
		}
		pkgs = append(pkgs, Package{Name: name, Version: version})
	}
	return pkgs
}

// MatchComponents returns the bom-refs of the components of bom that pkgs
// declare, in the order the components are listed. A declaration without a
// version matches every version of the package; a declaration with one
// matches that version only.
func MatchComponents(ctx context.Context, bom *cdx.BOM, ecosystem config.PackagesDirectiveType, pkgs []Package) []string {
	if bom == nil || len(pkgs) == 0 {
		return nil
	}

	purlType, ok := purlTypes[ecosystem]
	if !ok {
		return nil
	}

	byName := make(map[string][]Package, len(pkgs))
	for _, pkg := range pkgs {
		key := nameKey(purlType, pkg.Name)
		byName[key] = append(byName[key], pkg)
	}

	matched := make(map[string]struct{}, len(pkgs))
	var refs []string
	walkComponents(bom, func(comp *cdx.Component) {
		if comp.BOMRef == "" || comp.PackageURL == "" {
			return
		}
		purl, err := packageurl.FromString(comp.PackageURL)
		if err != nil || purl.Type != purlType {
			return
		}
		key := nameKey(purlType, fullName(purl))
		for _, pkg := range byName[key] {
			if pkg.Version != "" && pkg.Version != purl.Version {
				continue
			}
			refs = append(refs, comp.BOMRef)
			matched[key] = struct{}{}
			break
		}
	})

	for _, pkg := range pkgs {
		if _, ok := matched[nameKey(purlType, pkg.Name)]; !ok {
			logboek.Context(ctx).Debug().LogF("declared %s package %q matches no component of the SBOM\n", ecosystem, pkg.Name)
		}
	}

	if len(refs) == 0 {
		return nil
	}

	return lo.Uniq(refs)
}

// AddRootEdge records refs as direct dependencies of the metadata component of
// bom, merging with an edge already sourced there. Nothing happens when the
// root has no bom-ref or refs is empty.
func AddRootEdge(bom *cdx.BOM, refs []string) {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.BOMRef == "" || len(refs) == 0 {
		return
	}
	root := bom.Metadata.Component.BOMRef

	deps := lo.FromPtr(bom.Dependencies)
	for i := range deps {
		if deps[i].Ref != root {
			continue
		}
		deps[i].Dependencies = lo.ToPtr(lo.Uniq(append(lo.FromPtr(deps[i].Dependencies), refs...)))
		bom.Dependencies = &deps
		return
	}

	deps = append(deps, cdx.Dependency{Ref: root, Dependencies: lo.ToPtr(lo.Uniq(refs))})
	bom.Dependencies = &deps
}

var purlTypes = map[config.PackagesDirectiveType]string{
	config.PackagesDirectiveTypeGoMod:          packageurl.TypeGolang,
	config.PackagesDirectiveTypeJavaScriptNpm:  packageurl.TypeNPM,
	config.PackagesDirectiveTypeJavaScriptYarn: packageurl.TypeNPM,
	config.PackagesDirectiveTypeJavaScriptPnpm: packageurl.TypeNPM,
	config.PackagesDirectiveTypeRustCargo:      packageurl.TypeCargo,
	config.PackagesDirectiveTypePythonPoetry:   packageurl.TypePyPi,
	config.PackagesDirectiveTypePythonUV:       packageurl.TypePyPi,
	config.PackagesDirectiveTypePythonPip:      packageurl.TypePyPi,
	config.PackagesDirectiveTypeLuaRock:        "luarocks",
	config.PackagesDirectiveTypeOSPM:           packageurl.TypeGeneric,
}

var pypiSeparatorPattern = regexp.MustCompile(`[-_.]+`)

// nameKey canonicalizes a package name the way the purl of its type does, so a
// declaration and a component spell the same package the same way: Go and npm
// names are case-insensitive, PyPI names fold `_`, `-` and `.` runs.
func nameKey(purlType, name string) string {
	switch purlType {
	case packageurl.TypeGolang, packageurl.TypeNPM:
		return strings.ToLower(name)
	case packageurl.TypePyPi:
		return strings.ToLower(pypiSeparatorPattern.ReplaceAllString(name, "-"))
	default:
		return name
	}
}

// fullName joins the namespace and name of a purl back into the package name
// of its ecosystem: a Go module path, a scoped npm package.
func fullName(purl packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}
	return purl.Namespace + "/" + purl.Name
}

func walkComponents(bom *cdx.BOM, visit func(*cdx.Component)) {
	var walk func([]cdx.Component)
	walk = func(components []cdx.Component) {
		for i := range components {
			visit(&components[i])
			walk(lo.FromPtr(components[i].Components))
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		walk(lo.FromPtr(bom.Metadata.Component.Components))
	}
	walk(lo.FromPtr(bom.Components))
}
