package shippedscope

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
)

// PropertyJSBundles is written as "unknown" on a package an observed bundle output named
// when that output no longer holds the bytes it was observed with: whether the package
// still ships in it cannot be shown either way. Like the other unknown markers it survives
// merges, so an image importing from this one does not take the package for absent.
const PropertyJSBundles = "werf:js-bundles"

const (
	propertyJSBundlesUnknown = "unknown"

	// Marks an occurrence as a bundle output, not a file of the package: it is shared by
	// every package the output holds and grants none of them exclusive ownership.
	bundleEvidencePrefix   = "werf:js-bundle:"
	bundleEvidenceV1Prefix = bundleEvidencePrefix + "v1:"

	maxJSObserverLogBytes   int64 = 64 << 20
	maxJSObserverWarnings         = 8
	maxJSObserverWarningLen       = 512
	maxBundleOutputPathLen        = 4096
	maxNPMNameLen                 = 214
	maxNPMVersionLen              = 256
)

var (
	npmNamePattern    = regexp.MustCompile(`^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$`)
	npmVersionPattern = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$`)
)

type BundlePackage struct {
	Name    string
	Version string
}

// BundleOutput is the last record the build's JavaScript observer left for one output.
// Verified means the image holds the recorded bytes at the recorded path; an output
// rewritten, moved or removed after it was observed is unverified, and its packages can be
// shown neither present nor absent by it.
type BundleOutput struct {
	Path     string
	Digest   string
	Packages []BundlePackage
	Verified bool
}

// A record too malformed to name its packages is only warned about: there is no package to
// mark unknown, and it does not make every package unknown either. A package only such a
// record named is judged by its files, as if no bundle had been observed.
func bundleOutputs(ctx context.Context, index *FileIndex, manifests map[string][]byte) []BundleOutput {
	if _, ok := index.Files[jsobserver.LogPath]; !ok {
		return nil
	}
	delete(index.Files, jsobserver.LogPath)
	body, ok := manifests[jsobserver.LogPath]
	delete(manifests, jsobserver.LogPath)
	if !ok {
		logboek.Context(ctx).Warn().LogF("WARNING: JavaScript bundle observer log %s is over %d bytes or a hardlink and is not read; bundled packages are not proven shipped by it\n", jsobserver.LogPath, maxJSObserverLogBytes)

		return nil
	}

	records := make(map[string]BundleOutput)
	invalid := 0
	var warnings []string
	for len(body) > 0 {
		line := body
		body = nil
		if end := bytes.IndexByte(line, '\n'); end >= 0 {
			line, body = line[:end], line[end+1:]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var event jsobserver.Event
		if err := json.Unmarshal(line, &event); err != nil || event.Version != jsobserver.ProtocolVersion {
			invalid++

			continue
		}
		if event.Warning != "" && len(warnings) < maxJSObserverWarnings {
			warning := event.Warning
			if len(warning) > maxJSObserverWarningLen {
				warning = warning[:maxJSObserverWarningLen]
			}
			if !slices.Contains(warnings, warning) {
				warnings = append(warnings, warning)
			}
		}

		for _, output := range event.Outputs {
			record, valid := bundleRecord(index, output)
			if !valid {
				invalid++
			}
			records[output.Path] = record
		}
	}

	for _, warning := range warnings {
		logboek.Context(ctx).Warn().LogF("WARNING: JavaScript bundle observer: %q\n", warning)
	}
	if invalid > 0 {
		logboek.Context(ctx).Warn().LogF("WARNING: %d JavaScript bundle observer records could not be read; the packages they name are not proven shipped by them\n", invalid)
	}

	var outputs []BundleOutput
	for _, file := range slices.Sorted(maps.Keys(records)) {
		if len(records[file].Packages) > 0 {
			outputs = append(outputs, records[file])
		}
	}

	return outputs
}

// An empty output yields no packages: its digest is every empty file's.
func bundleRecord(index *FileIndex, output jsobserver.Output) (BundleOutput, bool) {
	record := BundleOutput{Path: output.Path, Digest: output.Digest}
	valid := validBundleOutputPath(output.Path) && validDigest(output.Digest)
	for _, pkg := range output.Packages {
		bundlePackage := BundlePackage{Name: pkg.Name, Version: pkg.Version}
		if !validBundlePackage(bundlePackage) {
			valid = false

			continue
		}
		if !slices.Contains(record.Packages, bundlePackage) {
			record.Packages = append(record.Packages, bundlePackage)
		}
	}

	file, ok := index.Files[output.Path]
	record.Verified = ok && validDigest(output.Digest) && file.Digest == output.Digest && validBundleOutputPath(output.Path)
	if record.Verified && file.Size == 0 {
		return BundleOutput{Path: output.Path}, valid
	}

	return record, valid
}

// BundleComponents names the packages verified bundle outputs hold that none of boms
// declares — a package whose node_modules a later stage pruned leaves no installed record
// for a scan to find. Each is a bare npm component, name, version and purl, with nothing
// else known about it.
func BundleComponents(_ context.Context, filesets *Filesets, boms []*cdx.BOM) []cdx.Component {
	if filesets == nil {
		return nil
	}

	declared := make(map[componentKey]bool)
	for _, bom := range boms {
		if bom == nil {
			continue
		}
		walkComponents(bom, func(comp *cdx.Component) {
			if key, ok := keyOfComponent(comp); ok {
				declared[key] = true
			}
		})
	}

	components := make(map[string]cdx.Component)
	for _, output := range filesets.Bundles {
		if !output.Verified {
			continue
		}
		for _, pkg := range output.Packages {
			purl := npmPackageURL(pkg)
			if _, ok := components[purl]; ok || declared[bundleKey(pkg)] {
				continue
			}
			components[purl] = cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				BOMRef:     purl,
				Name:       pkg.Name,
				Version:    pkg.Version,
				PackageURL: purl,
			}
		}
	}

	return slices.SortedFunc(maps.Values(components), func(a, b cdx.Component) int {
		return cmp.Compare(a.PackageURL, b.PackageURL)
	})
}

// RecordBundleOccurrences writes onto every npm component the verified outputs that hold
// it, beside its file evidence, and PropertyJSBundles onto those an unverified output
// names. An earlier image's record of an output at a path this image's observer recorded
// again is replaced; the rest of what earlier images recorded is kept, since an import may
// have moved those outputs anywhere. A package no output names is left as it was: a bundle
// leaving a package out says nothing about its installed files.
//
// Returns the number of components given bundle evidence.
func RecordBundleOccurrences(_ context.Context, bom *cdx.BOM, filesets *Filesets) int {
	if bom == nil || filesets == nil {
		return 0
	}

	proven := make(map[componentKey][]cdx.EvidenceOccurrence)
	unknown := make(map[componentKey]bool)
	for _, output := range filesets.Bundles {
		for _, pkg := range output.Packages {
			if !output.Verified {
				unknown[bundleKey(pkg)] = true

				continue
			}
			proven[bundleKey(pkg)] = append(proven[bundleKey(pkg)], cdx.EvidenceOccurrence{
				Location:          output.Path,
				AdditionalContext: bundleEvidenceV1Prefix + output.Digest,
			})
		}
	}

	recorded := 0
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok || key.ecosystem != EcosystemJavaScript {
			return
		}

		if unknown[key] && !slices.Contains(lo.FromPtr(comp.Properties), cdx.Property{Name: PropertyJSBundles, Value: propertyJSBundlesUnknown}) {
			comp.Properties = lo.ToPtr(append(lo.FromPtr(comp.Properties), cdx.Property{Name: PropertyJSBundles, Value: propertyJSBundlesUnknown}))
		}

		outputs, ok := proven[key]
		if !ok {
			return
		}
		recorded++

		rewritten := lo.SliceToMap(outputs, func(occurrence cdx.EvidenceOccurrence) (string, bool) { return occurrence.Location, true })
		if comp.Evidence == nil {
			comp.Evidence = &cdx.Evidence{}
		}
		occurrences := lo.Filter(lo.FromPtr(comp.Evidence.Occurrences), func(occurrence cdx.EvidenceOccurrence, _ int) bool {
			return !strings.HasPrefix(occurrence.AdditionalContext, bundleEvidencePrefix) || !rewritten[occurrence.Location]
		})
		occurrences = append(occurrences, outputs...)
		comp.Evidence.Occurrences = &occurrences
	})

	return recorded
}

// A record this werf cannot read, including a later format, makes the bundles unknown.
func bundleOccurrences(comp *cdx.Component) ([]Occurrence, bool) {
	unknown := lo.ContainsBy(lo.FromPtr(comp.Properties), func(property cdx.Property) bool {
		return property.Name == PropertyJSBundles
	})
	if comp.Evidence == nil {
		return nil, unknown
	}

	var occurrences []Occurrence
	for _, occurrence := range lo.FromPtr(comp.Evidence.Occurrences) {
		if !strings.HasPrefix(occurrence.AdditionalContext, bundleEvidencePrefix) {
			continue
		}

		digest, ok := strings.CutPrefix(occurrence.AdditionalContext, bundleEvidenceV1Prefix)
		if !ok || !validDigest(digest) || !validBundleOutputPath(occurrence.Location) {
			unknown = true

			continue
		}
		occurrences = append(occurrences, Occurrence{Path: occurrence.Location, Digest: digest})
	}

	return occurrences, unknown
}

func bundleKey(pkg BundlePackage) componentKey {
	return componentKey{
		ecosystem: EcosystemJavaScript,
		name:      canonicalName(EcosystemJavaScript, pkg.Name),
		version:   pkg.Version,
	}
}

func npmPackageURL(pkg BundlePackage) string {
	namespace, name := "", strings.ToLower(pkg.Name)
	if scope, rest, ok := strings.Cut(name, "/"); ok {
		namespace, name = scope, rest
	}
	purl := packageurl.NewPackageURL(packageurl.TypeNPM, namespace, name, pkg.Version, nil, "")

	return purl.ToString()
}

// The identity must also survive the purl it is matched by unchanged.
func validBundlePackage(pkg BundlePackage) bool {
	if len(pkg.Name) > maxNPMNameLen || len(pkg.Version) > maxNPMVersionLen ||
		!npmNamePattern.MatchString(pkg.Name) || !npmVersionPattern.MatchString(pkg.Version) {
		return false
	}

	key, ok := keyOfComponent(&cdx.Component{PackageURL: npmPackageURL(pkg)})

	return ok && key == bundleKey(pkg)
}

func validBundleOutputPath(file string) bool {
	return len(file) <= maxBundleOutputPathLen && path.IsAbs(file) && path.Clean(file) == file &&
		!strings.ContainsRune(file, 0) && file != jsobserver.LogPath
}

func validDigest(digest string) bool {
	hex, ok := strings.CutPrefix(digest, digestPrefix)

	return ok && len(hex) == 64 && strings.IndexFunc(hex, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
	}) < 0
}
