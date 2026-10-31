package build

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"github.com/werf/logboek"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// The scanner writes where it saw a component as one property per location: the path the
// file has, and the path it was reached by where a symlink led to it.
const (
	scannerLocationPrefix           = "syft:location:"
	scannerLocationPathSuffix       = ":path"
	scannerLocationAccessPathSuffix = ":accessPath"
)

// importScopeBackend is the copy backend the stage applied its imports with, as that
// stage recorded it when it was built.
//
// The include and exclude paths of one import mean different things to the two backends,
// so which of them copied decides what the import carried. The run reading this is not
// necessarily the run that did the copying: a stage reused from the cache was built by
// another one, possibly with the other builder, and the backend of the current run would
// then answer for a copy it never performed.
//
// An image reused whole by its content anchor skips its stages altogether, so none of them
// holds a stage image in this run; what copied the import is then read from the record the
// published stage chain of that same image carries.
func importScopeBackend(stg stage.Interface, published func() (map[stage.StageName]string, error)) (nativegate.ImportBackend, error) {
	stageImage := stg.GetStageImage()
	if stageImage == nil || stageImage.Image == nil || stageImage.Image.GetStageDesc() == nil || stageImage.Image.GetStageDesc().Info == nil {
		backends, err := published()
		if err != nil {
			return "", fmt.Errorf("no-data: stage %s carries no built stage the import copy backend could be read from, and the published stage chain of the image could not be read: %w", stg.Name(), err)
		}
		recorded, stated := backends[stg.Name()]
		if !stated {
			return "", fmt.Errorf("no-data: stage %s carries no built stage the import copy backend could be read from, and the published stage chain of the image states no such stage", stg.Name())
		}

		return namedImportBackend(stg.Name(), recorded)
	}
	var record sbomStageRecord
	if err := json.Unmarshal([]byte(stageImage.Image.GetStageDesc().Info.Labels[imagePkg.WerfSBOMStageLabel]), &record); err != nil {
		return "", fmt.Errorf("no-data: read the SBOM stage record of %s: %w", stg.Name(), err)
	}
	if record.Stage != stg.Name() {
		return "", fmt.Errorf("no-data: the SBOM stage record of %s belongs to stage %s", stg.Name(), record.Stage)
	}

	return namedImportBackend(stg.Name(), record.ImportBackend)
}

// publishedImportBackends reads, at most once, the import copy backend every stage of the
// published stage chain of the image records. It is what remains to read from when the
// image is reused whole and its stages are never processed in this run.
func publishedImportBackends(ctx context.Context, img *image.Image) func() (map[stage.StageName]string, error) {
	var (
		backends map[stage.StageName]string
		err      error
		read     bool
	)

	return func() (map[stage.StageName]string, error) {
		if read {
			return backends, err
		}
		read = true
		backends, err = readPublishedImportBackends(ctx, img)

		return backends, err
	}
}

func readPublishedImportBackends(ctx context.Context, img *image.Image) (map[stage.StageName]string, error) {
	stageDesc := img.GetLastNonEmptyStageDesc()
	if stageDesc == nil {
		return nil, fmt.Errorf("image %s has no published stage", img.GetName())
	}
	provenance, err := resolveSBOMStageProvenance(ctx, stageDesc, docker_registry.API().GetRepoImageConfigFile)
	if err != nil {
		return nil, err
	}
	backends := make(map[stage.StageName]string, len(provenance.Snapshots))
	for _, snapshot := range provenance.Snapshots {
		backends[snapshot.Stage] = snapshot.ImportBackend
	}

	return backends, nil
}

func namedImportBackend(stageName stage.StageName, recorded string) (nativegate.ImportBackend, error) {
	switch recorded {
	case "copy-recurse":
		return nativegate.ImportBackendCopyRecurse, nil
	case "rsync":
		return nativegate.ImportBackendRsync, nil
	}

	return "", fmt.Errorf("no-data: stage %s records no import copy backend", stageName)
}

// scopeImportBOM answers what an import source contributes to the image that imports it:
// the components of the source's own SBOM that it says occur, in the source image, at a
// path at least one of the import directives carries.
//
// An import copies a part of another image. The document of that other image describes
// the whole of it - the toolchain it was built with, the sources it compiled, the
// packages of an environment none of which this image received - and a component whose
// every occurrence stands outside the copied scope is a statement about the donor, not
// about this image.
//
// A component the donor states no whereabouts of at all cannot be placed either way. It is
// kept where the import takes the whole of the source image, since then there is no part
// of the donor it could belong to instead; it is dropped where the donor says in so many
// words that it describes no files of the image; and otherwise the import yields no data,
// because silently dropping it would quietly narrow what the importing image is said to be
// made of, and silently keeping it would claim files nothing ties to this image.
//
// What survives is unchanged, occurrences included: where a kept component sits in this
// image is settled by the verification, which reads both snapshots, and overwriting the
// donor's paths from a lexical mapping here would only put a guess in their place.
func scopeImportBOM(ctx context.Context, bom *cdx.BOM, scopes []nativegate.ImportScope) (*cdx.BOM, error) {
	if bom == nil {
		return nil, nil
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("no-data: an import source SBOM is read for no import directive")
	}
	carried := func(path string) (bool, error) {
		for _, scope := range scopes {
			carries, err := nativegate.ImportCarries(scope, path)
			if err != nil {
				return false, err
			}
			if carries {
				return true, nil
			}
		}

		return false, nil
	}
	whole, err := carriesWholeImage(scopes)
	if err != nil {
		return nil, err
	}

	scoped := *bom
	components, err := scopedComponents(ctx, bom.Components, carried, whole)
	if err != nil {
		return nil, err
	}
	scoped.Components = components
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		metadata := *bom.Metadata
		component := *bom.Metadata.Component
		nested, err := scopedComponents(ctx, component.Components, carried, whole)
		if err != nil {
			return nil, err
		}
		component.Components = nested
		metadata.Component = &component
		scoped.Metadata = &metadata
	}
	scoped.Dependencies = scopedDependencies(bom.Dependencies, &scoped)

	return &scoped, nil
}

// carriesWholeImage answers whether the import copies the source image entire. Only a
// directive naming its root, filtering nothing out of it and read by a backend that takes
// a matched directory whole does; what the other backend keeps excluding inside it is not
// settled by the directive alone.
func carriesWholeImage(scopes []nativegate.ImportScope) (bool, error) {
	for _, scope := range scopes {
		if rootedImportPath(scope.FromPath) != "/" || len(scope.IncludePaths)+len(scope.ExcludePaths) > 0 {
			continue
		}
		if scope.Backend != nativegate.ImportBackendCopyRecurse {
			continue
		}
		carries, err := nativegate.ImportCarries(scope, "/")
		if err != nil {
			return false, err
		}
		if carries {
			return true, nil
		}
	}

	return false, nil
}

// rootedImportPath reads a path of a directive the way the copy does, so that the root is
// recognized however the recipe spelled it.
func rootedImportPath(raw string) string {
	if raw == "" {
		return ""
	}
	if !path.IsAbs(raw) {
		raw = "/" + raw
	}

	return path.Clean(raw)
}

// groupsOnly answers whether this component is nothing but a holder of the ones below it:
// a heading the donor's document hangs others off, with no identity of its own. A holder
// that names a package - anything with a purl, or a name and a version - is a claim about
// the image like any other and is answered for as one.
func groupsOnly(comp cdx.Component, held bool) bool {
	return held && comp.PackageURL == "" && comp.CPE == "" && comp.Version == ""
}

// describesNoFiles answers whether the donor states, explicitly, that this component
// describes nothing the image ships - a tool that built it, an environment it was built
// in, a package the scan named that was then judged absent. Only a statement counts: that
// a component happens to carry no occurrence is the very thing being decided, and reading
// it as the answer would decide everything by itself.
func describesNoFiles(comp cdx.Component) bool {
	if comp.Scope == cdx.ScopeExcluded {
		return true
	}
	for _, property := range lo.FromPtr(comp.Properties) {
		switch {
		case property.Name == shippedscope.PropertyFiles && property.Value == shippedscope.PropertyFilesNone:
			return true
		case property.Name == shippedscope.PropertyShipped && property.Value == shippedscope.PropertyShippedFalse:
			return true
		}
	}

	return false
}

func scopedComponents(ctx context.Context, components *[]cdx.Component, carried func(path string) (bool, error), whole bool) (*[]cdx.Component, error) {
	if components == nil {
		return nil, nil
	}
	kept := make([]cdx.Component, 0, len(*components))
	for _, comp := range *components {
		// A component holding the ones below it keeps whatever of them is carried,
		// and stays itself as long as anything it holds does.
		held := comp.Components != nil
		nested, err := scopedComponents(ctx, comp.Components, carried, whole)
		if err != nil {
			return nil, err
		}
		comp.Components = nested
		locations := whereabouts(comp)
		occurs, err := occursInScope(locations, carried)
		if err != nil {
			return nil, err
		}
		switch {
		// A holder keeps whatever of what it held the import carries, whatever is
		// said of the holder itself.
		case nested != nil:
		case describesNoFiles(comp):
			// Said of a component, this holds wherever the copy reached: an import
			// of the whole image is still no reason to claim what the source says
			// it does not ship, and neither is a path the copy carries.
			logboek.Context(ctx).Debug().LogF("SBOM import scope: drop %s %s, the source states it describes no files of the image\n", comp.Name, comp.Version)

			continue
		case occurs:
		case len(locations) > 0:
			// Every place the donor put it stands outside what was copied.
			logboek.Context(ctx).Debug().LogF("SBOM import scope: drop %s %s, no occurrence the import carries\n", comp.Name, comp.Version)

			continue
		case whole:
		case groupsOnly(comp, held):
			// It held only components this import leaves behind, and says nothing
			// of itself: what is left of it is an empty heading.
			logboek.Context(ctx).Debug().LogF("SBOM import scope: drop %s, a holder of components the import carries none of\n", comp.Name)

			continue
		default:
			return nil, fmt.Errorf("no-data: the source states no whereabouts of %s, so a partial import of it places nothing: either the source records where its components stand, or it marks this one as describing no files of the image", componentSubject(comp))
		}
		kept = append(kept, comp)
	}
	if len(kept) == 0 {
		return nil, nil
	}

	return &kept, nil
}

func componentSubject(comp cdx.Component) string {
	subject := comp.Name
	if comp.Version != "" {
		subject += " " + comp.Version
	}
	if comp.BOMRef != "" {
		subject += " (" + comp.BOMRef + ")"
	}

	return subject
}

// whereabouts is everywhere the donor says this component stands.
//
// The occurrences of the document answer alone wherever it carries them: they are the
// files the image holds, and a scanner's note of where it read a manifest is not evidence
// of the same kind (shippedscope.RecordOccurrences).
//
// What the scan recorded is read for one component and no other: one of an ecosystem that
// ships no files of its own, cataloged out of a dependency manifest, that werf said
// nothing about. Whether such a component is in the image at all is settled by the
// binaries, which answer with the composition they embed and are verified against it, so
// nothing the import carries goes unaccounted for when the listing is left behind; and a
// manifest listing a dependency does say, at least, that the listing is there. Those paths
// are the donor's own, since a cataloger's inputs are scanned under the full path they
// have in the image (managedinput.MaterializeCatalogerInputs), and a file the scan reached
// through a symlink is recorded under both spellings, either of which an import may name.
//
// For everything else the scan's record is not read at all. A package of a distribution is
// placed from the donor's own database, which names the files of the package rather than
// the database the scan read it out of, and one that database cannot place stays placed
// nowhere on purpose (shippedscope.RecomputeDonorPackages). And where werf stated
// something of a component's files itself, that statement is the answer and a scanner's
// location is no appeal against it: that they are unknown leaves the component placed
// nowhere, and the spellings that say it describes none are answered for before anything
// is placed at all.
func whereabouts(comp cdx.Component) []string {
	var locations []string
	for _, occurrence := range lo.FromPtr(lo.FromPtr(comp.Evidence).Occurrences) {
		if occurrence.Location != "" {
			locations = append(locations, occurrence.Location)
		}
	}
	if len(locations) > 0 || !readsScannerLocations(comp) {
		return locations
	}
	for _, property := range lo.FromPtr(comp.Properties) {
		if !strings.HasPrefix(property.Name, scannerLocationPrefix) || property.Value == "" {
			continue
		}
		if strings.HasSuffix(property.Name, scannerLocationPathSuffix) || strings.HasSuffix(property.Name, scannerLocationAccessPathSuffix) {
			locations = append(locations, property.Value)
		}
	}

	return locations
}

func readsScannerLocations(comp cdx.Component) bool {
	if !shippedscope.BinaryBackedComponent(&comp) {
		return false
	}

	return !lo.ContainsBy(lo.FromPtr(comp.Properties), func(property cdx.Property) bool {
		return property.Name == shippedscope.PropertyFiles
	})
}

func occursInScope(locations []string, carried func(path string) (bool, error)) (bool, error) {
	for _, location := range locations {
		carries, err := carried(location)
		if err != nil {
			return false, err
		}
		if carries {
			return true, nil
		}
	}

	return false, nil
}

// scopedDependencies keeps the edges between the components that remain. An edge to a
// component this import does not contribute names nothing of this image.
func scopedDependencies(dependencies *[]cdx.Dependency, scoped *cdx.BOM) *[]cdx.Dependency {
	if dependencies == nil {
		return nil
	}
	refs := map[string]struct{}{}
	var collect func(components *[]cdx.Component)
	collect = func(components *[]cdx.Component) {
		for _, comp := range lo.FromPtr(components) {
			refs[comp.BOMRef] = struct{}{}
			collect(comp.Components)
		}
	}
	collect(scoped.Components)
	if scoped.Metadata != nil && scoped.Metadata.Component != nil {
		refs[scoped.Metadata.Component.BOMRef] = struct{}{}
		collect(scoped.Metadata.Component.Components)
	}

	kept := make([]cdx.Dependency, 0, len(*dependencies))
	for _, dependency := range *dependencies {
		if _, known := refs[dependency.Ref]; !known {
			continue
		}
		if dependency.Dependencies != nil {
			depends := lo.Filter(*dependency.Dependencies, func(ref string, _ int) bool {
				_, known := refs[ref]

				return known
			})
			dependency.Dependencies = &depends
		}
		kept = append(kept, dependency)
	}
	if len(kept) == 0 {
		return nil
	}

	return &kept
}
