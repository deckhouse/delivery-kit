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
	"unicode"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
)

// PropertyJSBundles is written as "unknown" on a package an observed bundle output named
// when that output no longer holds the bytes it was observed with: whether the package
// still ships in it cannot be shown either way, and on every npm package when the image
// holds the observer log but it was not read. Like the other unknown markers it survives
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

	emptyFileDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	npmNamePattern    = regexp.MustCompile(`^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$`)
	npmVersionPattern = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$`)
)

type BundlePackage struct {
	Name    string
	Version string
}

// BundleOutput is a record the build's JavaScript observer left for one output, at the path
// it was observed at. Verified means the image holds the recorded bytes, at that path or
// wherever a later step of the build moved them. The last record of a path whose bytes the
// image holds nowhere is unverified, with the packages the records just before it named for
// the same bytes: those packages can be shown neither present nor absent.
// Unidentified are the packages it names under a name or version werf does not accept: none
// of them is proven shipped, and none can be shown absent either.
type BundleOutput struct {
	Path         string
	Digest       string
	Packages     []BundlePackage
	Unidentified []BundlePackage
	Verified     bool
}

// A record too malformed to name its packages is only warned about: there is no package to
// mark unknown, and it does not make every package unknown either. A package only such a
// record named is judged by its files, as if no bundle had been observed. A log the image
// holds but that is not read could name any package, so it reports every package unknown.
func bundleOutputs(ctx context.Context, index *FileIndex, manifests map[string][]byte) ([]BundleOutput, bool) {
	_, isFile := index.Files[jsobserver.LogPath]
	_, isSymlink := index.Symlinks[jsobserver.LogPath]
	if !isFile && !isSymlink && !index.unresolved[jsobserver.LogPath] {
		return nil, false
	}
	delete(index.Files, jsobserver.LogPath)
	body, ok := manifests[jsobserver.LogPath]
	delete(manifests, jsobserver.LogPath)
	if !ok {
		logboek.Context(ctx).Warn().LogF("WARNING: JavaScript bundle observer log %s is over %d bytes, a hardlink or a symlink and is not read; no npm package can be shown absent from the bundles\n", jsobserver.LogPath, maxJSObserverLogBytes)

		return nil, true
	}

	byDigest := indexByDigest(index)
	last := make(map[string]BundleOutput)
	verified := make(map[[2]string]BundleOutput)
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
			record, valid := bundleRecord(byDigest, output)
			if !valid {
				invalid++
			}
			// Builds of different package versions can render the same bytes, and either
			// build's copy may be the one that was moved before the path was written again,
			// or the one the image changed afterwards.
			if earlier, ok := last[record.Path]; ok && earlier.Digest == record.Digest {
				record = mergeBundleOutputs(earlier, record)
			}
			last[record.Path] = record
			if record.Verified {
				key := [2]string{record.Path, record.Digest}
				if earlier, ok := verified[key]; ok {
					record = mergeBundleOutputs(earlier, record)
				}
				verified[key] = record
			}
		}
	}

	for _, warning := range warnings {
		logboek.Context(ctx).Warn().LogF("WARNING: JavaScript bundle observer: %q\n", warning)
	}
	if invalid > 0 {
		logboek.Context(ctx).Warn().LogF("WARNING: %d JavaScript bundle observer records could not be read; the packages they name are not proven shipped by them\n", invalid)
	}

	// A record its path's later record overrides still holds whatever bytes it was observed
	// with, and those may have been moved before the path was written again.
	outputs := slices.Collect(maps.Values(verified))
	for _, record := range last {
		if !record.Verified {
			outputs = append(outputs, record)
		}
	}
	outputs = lo.Filter(outputs, func(output BundleOutput, _ int) bool { return len(output.Packages) > 0 || len(output.Unidentified) > 0 })
	slices.SortFunc(outputs, func(a, b BundleOutput) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Digest, b.Digest))
	})

	return outputs, false
}

func mergeBundleOutputs(earlier, record BundleOutput) BundleOutput {
	record.Packages = lo.Uniq(slices.Concat(earlier.Packages, record.Packages))
	if len(earlier.Unidentified) > 0 {
		record.Unidentified = lo.Uniq(slices.Concat(earlier.Unidentified, record.Unidentified))
	}

	return record
}

// An empty output yields no packages: its digest is every empty file's.
func bundleRecord(byDigest map[string][]string, output jsobserver.Output) (BundleOutput, bool) {
	record := BundleOutput{Path: output.Path, Digest: output.Digest}
	valid := validBundleOutputPath(output.Path) && validDigest(output.Digest)
	if output.Digest == emptyFileDigest {
		return BundleOutput{Path: output.Path}, valid
	}

	seen := make(map[BundlePackage]struct{}, len(output.Packages))
	for _, pkg := range output.Packages {
		bundlePackage := BundlePackage{Name: pkg.Name, Version: pkg.Version}
		if _, ok := seen[bundlePackage]; ok {
			continue
		}
		seen[bundlePackage] = struct{}{}
		if validBundlePackage(bundlePackage) {
			record.Packages = append(record.Packages, bundlePackage)

			continue
		}
		valid = false
		if boundedBundlePackage(bundlePackage) {
			record.Unidentified = append(record.Unidentified, bundlePackage)
		}
	}

	record.Verified = validBundleOutputPath(output.Path) && validDigest(output.Digest) && len(byDigest[output.Digest]) > 0

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
// names, or onto every one when the observer log was not read. Each occurrence keeps the
// path the output was observed at. Bundle occurrences the component already carries are
// kept, even at a path recorded again with other bytes: the earlier bytes may have been
// moved elsewhere, and only their digest is looked for. A package no output names is left
// as it was: a bundle leaving a package out says nothing about its installed files. A
// package an output names under a name werf does not accept is marked unknown too, whether
// or not the output is verified: its name proves nothing, but its files being gone does not
// make it absent.
//
// Returns the number of components given bundle evidence or marked unknown.
func RecordBundleOccurrences(ctx context.Context, bom *cdx.BOM, filesets *Filesets) int {
	if bom == nil || filesets == nil {
		return 0
	}

	proven := make(map[componentKey][]cdx.EvidenceOccurrence)
	unknown := make(map[componentKey]bool)
	unidentified := make(map[componentKey]bool)
	for _, output := range filesets.Bundles {
		for _, pkg := range output.Unidentified {
			unidentified[bundleKey(pkg)] = true
		}
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
	unidentifiedMarked := 0
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok || key.ecosystem != EcosystemJavaScript {
			return
		}

		outputs, isProven := proven[key]
		if unidentified[key] {
			unidentifiedMarked++
		}
		if filesets.BundlesUnknown || unknown[key] || unidentified[key] {
			if !slices.Contains(lo.FromPtr(comp.Properties), cdx.Property{Name: PropertyJSBundles, Value: propertyJSBundlesUnknown}) {
				comp.Properties = lo.ToPtr(append(lo.FromPtr(comp.Properties), cdx.Property{Name: PropertyJSBundles, Value: propertyJSBundlesUnknown}))
			}
			if !isProven {
				recorded++
			}
		}

		if !isProven {
			return
		}
		recorded++

		if comp.Evidence == nil {
			comp.Evidence = &cdx.Evidence{}
		}
		occurrences := lo.FromPtr(comp.Evidence.Occurrences)
		for _, output := range outputs {
			if !slices.Contains(occurrences, output) {
				occurrences = append(occurrences, output)
			}
		}
		comp.Evidence.Occurrences = &occurrences
	})

	if unidentifiedMarked > 0 {
		logboek.Context(ctx).Warn().LogF("WARNING: %d npm packages a JavaScript bundle observer record names under a name werf does not accept are marked unknown in the bundles\n", unidentifiedMarked)
	}

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

// A package too malformed to stand for any installed component is only counted invalid.
func boundedBundlePackage(pkg BundlePackage) bool {
	return pkg.Name != "" && pkg.Version != "" && len(pkg.Name) <= maxNPMNameLen && len(pkg.Version) <= maxNPMVersionLen &&
		!strings.ContainsFunc(pkg.Name+pkg.Version, unicode.IsControl)
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
