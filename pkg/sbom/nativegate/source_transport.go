package nativegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	ospm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const (
	originalsProperty = "dk:originals/v1"
	pmIndexPath       = "/var/lib/pm/index.json"
)

// SourceSnapshot is an observed stage boundary, not a reconstruction from package payloads.
type SourceSnapshot struct {
	Stage   string
	Index   *shippedscope.FileIndex
	Receipt *sources.Receipt
	Imports []SourceImport
}

// SourceImport pairs one actual source image with its scoped copy directive.
type SourceImport struct {
	Index   *shippedscope.FileIndex
	BOM     *cdx.BOM
	Receipt *sources.Receipt
	Scope   ImportScope
}

type originalFileRecord struct {
	SHA256   string            `json:"sha256"`
	Size     int64             `json:"size"`
	Bindings []originalBinding `json:"bindings"`
}

type originalsCatalog struct {
	Schema  string                        `json:"schema"`
	Sources map[string]sources.Source     `json:"sources"`
	Files   map[string]originalFileRecord `json:"files"`
}

type sourceEvidence struct {
	index    *shippedscope.FileIndex
	matches  originalMatches
	resolved map[string]*resolvedSource
	// unverified holds the paths an earlier stage bound to an original and this one keeps
	// with other bytes. It lives for this verification only: a lost binding is nothing to
	// publish, and equal bytes elsewhere do not re-establish the one that was lost.
	unverified map[string]bool
}

func (e *sourceEvidence) resolve(ctx context.Context, source sources.Source) (*resolvedSource, error) {
	if _, err := sources.Encode(&sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}}); err != nil {
		return nil, fmt.Errorf("invalid source receipt: %w", err)
	}
	// Raw Packet spelling is preserved; only whitespace is insignificant for reuse.
	var packet bytes.Buffer
	if err := json.Compact(&packet, source.Packet); err != nil {
		return nil, err
	}
	for _, known := range e.resolved {
		var existing bytes.Buffer
		if err := json.Compact(&existing, known.Source.Packet); err != nil {
			return nil, err
		}
		if source.Registry == known.Source.Registry && source.Platform == known.Source.Platform && bytes.Equal(packet.Bytes(), existing.Bytes()) {
			return known, nil
		}
	}
	resolved, err := resolveOriginalSource(ctx, source)
	if err != nil {
		return nil, err
	}
	if known, exists := e.resolved[resolved.ID]; exists {
		var existing bytes.Buffer
		if err := json.Compact(&existing, known.Source.Packet); err != nil {
			return nil, err
		}
		if !bytes.Equal(packet.Bytes(), existing.Bytes()) {
			return nil, fmt.Errorf("invalid: conflicting Packet metadata for original source %s", resolved.ID)
		}
	}
	e.resolved[resolved.ID] = resolved
	return resolved, nil
}

func readOriginalsCatalog(bom *cdx.BOM) (*originalsCatalog, error) {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Properties == nil {
		return nil, nil
	}
	var result *originalsCatalog
	for _, property := range *bom.Metadata.Properties {
		if property.Name != originalsProperty {
			if strings.HasPrefix(property.Name, "dk:originals/") {
				return nil, fmt.Errorf("unsupported inherited originals catalog property %s", property.Name)
			}
			continue
		}
		if result != nil {
			return nil, fmt.Errorf("invalid: duplicate originals catalog")
		}
		result = new(originalsCatalog)
		if err := decode([]byte(property.Value), result); err != nil {
			return nil, fmt.Errorf("invalid originals catalog: %w", err)
		}
		if result.Schema != originalsProperty || result.Sources == nil || result.Files == nil {
			return nil, fmt.Errorf("no-data: incomplete or unsupported originals catalog")
		}
	}
	return result, nil
}

func (e *sourceEvidence) inherit(ctx context.Context, index *shippedscope.FileIndex, bom *cdx.BOM) (originalMatches, error) {
	catalog, err := readOriginalsCatalog(bom)
	if err != nil {
		return nil, err
	}
	matches := make(originalMatches)
	if catalog == nil {
		return matches, nil
	}
	expected := make(map[string]map[string]shippedscope.File)
	for _, name := range slices.Sorted(maps.Keys(catalog.Files)) {
		record := catalog.Files[name]
		file, exists := index.Files[name]
		if !exists || file.Digest != record.SHA256 || file.Size != record.Size || len(record.Bindings) == 0 {
			return nil, fmt.Errorf("invalid: originals catalog does not match source snapshot at %s", name)
		}
		for _, binding := range record.Bindings {
			source, exists := catalog.Sources[binding.Source]
			if !exists {
				return nil, fmt.Errorf("no-data: missing source %s for %s", binding.Source, name)
			}
			resolved, err := e.resolve(ctx, source)
			if err != nil {
				return nil, err
			}
			if resolved.ID != binding.Source {
				return nil, fmt.Errorf("invalid: original source identity mismatch at %s", name)
			}
			entry, err := resolved.Original.Lookup(binding.Path)
			if err != nil {
				return nil, fmt.Errorf("original %s: %w", name, err)
			}
			if entry.SHA256 != file.Digest {
				return nil, fmt.Errorf("invalid: original bytes mismatch at %s", name)
			}
			if expected[resolved.ID] == nil {
				expected[resolved.ID] = make(map[string]shippedscope.File)
			}
			if previous, exists := expected[resolved.ID][binding.Path]; exists && previous != file {
				return nil, fmt.Errorf("invalid: contradictory original bytes at %s", name)
			}
			expected[resolved.ID][binding.Path] = file
		}
		matches[name] = sortedOriginalBindings(record.Bindings)
	}
	for _, source := range slices.Sorted(maps.Keys(expected)) {
		if err := verifyOriginalFiles(ctx, e.resolved[source].Original, expected[source]); err != nil {
			return nil, fmt.Errorf("original source %s: %w", source, err)
		}
	}
	return matches, nil
}

func (e *sourceEvidence) installed(ctx context.Context, snapshot SourceSnapshot) (originalMatches, error) {
	if snapshot.Receipt == nil {
		if _, exists := snapshot.Index.Files[pmIndexPath]; exists {
			return nil, fmt.Errorf("no-data: pm index has no original source receipt at %s", snapshot.Stage)
		}
		return make(originalMatches), nil
	}
	available := make(map[string]*original.OriginalPackage)
	for _, source := range snapshot.Receipt.Sources {
		resolved, err := e.resolve(ctx, source)
		if err != nil {
			return nil, err
		}
		available[resolved.ID] = resolved.Original
	}
	return matchSnapshotOriginals(ctx, snapshot.Index, available)
}

// A Deckhouse build opens and installs packages at the package stage; a dependency stage
// may copy that metadata in with a declared import. Anywhere else, pm metadata that
// appears or changes is a local install this gate cannot attribute to opened sources.
// Removal is cleanup and stays allowed.
func declaredImport(snapshot SourceSnapshot) bool {
	return strings.HasPrefix(snapshot.Stage, "dependencies") && len(snapshot.Imports) > 0
}

func checkInstallBoundary(previous, current SourceSnapshot) error {
	for _, path := range []string{pmIndexPath, sources.DefaultPath} {
		before, had := previous.Index.Files[path]
		after, has := current.Index.Files[path]
		if has && (!had || before != after) {
			return fmt.Errorf("no-data: %s changes pm install metadata outside a package stage: %s", current.Stage, path)
		}
	}
	changed, err := changedReceipt(previous.Receipt, current.Receipt)
	if err != nil {
		return err
	}
	if changed {
		return fmt.Errorf("no-data: %s opens package sources outside a package stage", current.Stage)
	}

	return nil
}

func changedReceipt(previous, current *sources.Receipt) (bool, error) {
	if current == nil {
		return false, nil
	}
	encoded, err := sources.Encode(current)
	if err != nil {
		return false, fmt.Errorf("invalid source receipt: %w", err)
	}
	if previous == nil {
		return true, nil
	}
	known, err := sources.Encode(previous)
	if err != nil {
		return false, fmt.Errorf("invalid source receipt: %w", err)
	}

	return !bytes.Equal(encoded, known), nil
}

func collectSourceEvidence(ctx context.Context, snapshots []SourceSnapshot, base *cdx.BOM) (*sourceEvidence, error) {
	if len(snapshots) == 0 || snapshots[0].Stage != "from" {
		return nil, fmt.Errorf("no-data: original sources require the actual base snapshot")
	}
	e := &sourceEvidence{resolved: make(map[string]*resolvedSource)}
	for i, snapshot := range snapshots {
		if snapshot.Index == nil || snapshot.Index.Incomplete {
			return nil, fmt.Errorf("no-data: incomplete source snapshot for %s", snapshot.Stage)
		}
		if i == 0 {
			inherited, err := e.inherit(ctx, snapshot.Index, base)
			if err != nil {
				return nil, err
			}
			var installed originalMatches
			catalog, err := readOriginalsCatalog(base)
			if err != nil {
				return nil, err
			}
			if snapshot.Receipt != nil || catalog == nil {
				installed, err = e.installed(ctx, snapshot)
				if err != nil {
					return nil, err
				}
			}
			for name, bindings := range installed {
				if len(inherited[name]) == 0 {
					inherited[name] = bindings
				}
			}
			e.index, e.matches = snapshot.Index, inherited
			continue
		}
		next := make(originalMatches)
		if snapshot.Stage != "packages" && !declaredImport(snapshot) {
			if err := checkInstallBoundary(snapshots[i-1], snapshot); err != nil {
				return nil, err
			}
		}
		if strings.HasPrefix(snapshot.Stage, "dependencies") {
			for name, bindings := range e.matches {
				if file, exists := snapshot.Index.Files[name]; exists && file == e.index.Files[name] {
					next[name] = slices.Clone(bindings)
				}
			}
		} else {
			var err error
			next, err = carryOriginalMatches(e.index, e.matches, snapshot.Index)
			if err != nil {
				return nil, err
			}
		}
		if snapshot.Stage == "packages" {
			installed, err := e.installed(ctx, snapshot)
			if err != nil {
				return nil, err
			}
			for name, bindings := range installed {
				if len(e.matches[name]) > 0 && e.index.Files[name] == snapshot.Index.Files[name] {
					continue
				}
				next[name] = sortedOriginalBindings(append(next[name], bindings...))
			}
		}
		for _, imported := range snapshot.Imports {
			if imported.Index == nil || imported.Index.Incomplete {
				return nil, fmt.Errorf("no-data: missing imported source snapshot")
			}
			matches, err := e.inherit(ctx, imported.Index, imported.BOM)
			if err != nil {
				return nil, err
			}
			catalog, err := readOriginalsCatalog(imported.BOM)
			if err != nil {
				return nil, err
			}
			if catalog == nil {
				matches, err = e.installed(ctx, SourceSnapshot{Stage: "import source", Index: imported.Index, Receipt: imported.Receipt})
				if err != nil {
					return nil, err
				}
			}
			carried, err := importOriginalMatches(ctx, imported.Index, matches, e.index, snapshot.Index, imported.Scope)
			if err != nil {
				return nil, err
			}
			// Identical bytes make the import one more candidate origin, not the chosen one.
			for name, bindings := range carried {
				next[name] = sortedOriginalBindings(append(next[name], bindings...))
			}
		}
		unverified := e.carryUnverified(snapshot.Index, next)
		e.index, e.matches, e.unverified = snapshot.Index, next, unverified
	}
	return e, nil
}

// carryUnverified remembers only a path this stage still holds whose actual binding it
// dropped; a path that was never bound stays unclaimed, and a new binding or the removal
// of the path forgets it.
func (e *sourceEvidence) carryUnverified(index *shippedscope.FileIndex, next originalMatches) map[string]bool {
	unverified := make(map[string]bool)
	for name := range index.Files {
		if len(next[name]) > 0 {
			continue
		}
		if len(e.matches[name]) > 0 || e.unverified[name] {
			unverified[name] = true
		}
	}

	return unverified
}

func (c *Catalog) addOriginalSources(ctx context.Context, e *sourceEvidence) error {
	for name, bindings := range e.matches {
		if len(bindings) == 0 {
			return fmt.Errorf("no-data: missing original binding at %s", name)
		}
		sourceID := bindings[0].Source
		if slices.ContainsFunc(bindings, func(binding originalBinding) bool { return binding.Source != sourceID }) {
			continue
		}
		// Package attribution needs a unique source, without choosing an original path.
		source := e.resolved[sourceID]
		if source == nil {
			return fmt.Errorf("no-data: unresolved original source %s at %s", sourceID, name)
		}
		if _, exists := c.Components[source.ID]; !exists {
			bom := ospm.ConvertToCycloneDX(ctx, map[string]ospm.PmPackageInfo{source.Package.Name: source.Package}, "")
			if bom == nil || bom.Components == nil || len(*bom.Components) != 1 {
				return fmt.Errorf("invalid: original source has no package metadata")
			}
			component := (*bom.Components)[0]
			component.BOMRef = source.ID
			component.PackageURL = packageurl.NewPackageURL("generic", "", source.Package.Name, source.Package.Version, nil, "").ToString()
			properties := []cdx.Property{{Name: cyclonedxutil.PropertyOriginalSource, Value: source.ID}}
			if component.Properties != nil {
				for _, property := range *component.Properties {
					if property.Name != "werf:pm:containerFactoryVersion" {
						properties = append(properties, property)
					}
				}
			}
			component.Properties = &properties
			c.Components[source.ID] = component
		}
		c.Records = append(c.Records, Record{Path: name, SHA256: e.index.Files[name].Digest, Origin: "pm", Namespace: source.ID, Owners: []string{source.ID}, Components: []string{source.ID}})
	}
	return nil
}

// Packet bytes are the producer's, as sources.Encode keeps them: the default HTML escaping
// would rewrite markup and line separators, and a fresh receipt for the same original would
// then no longer compare equal to the inherited one.
func encodeOriginalsCatalog(catalog originalsCatalog) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(catalog); err != nil {
		return nil, err
	}

	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func (e *sourceEvidence) attach(bom *cdx.BOM) error {
	if e.index == nil || e.index.Incomplete {
		return fmt.Errorf("no-data: cannot publish an incomplete original snapshot")
	}
	catalog := originalsCatalog{Schema: originalsProperty, Sources: make(map[string]sources.Source), Files: make(map[string]originalFileRecord)}
	for name, bindings := range e.matches {
		file, exists := e.index.Files[name]
		if !exists || len(bindings) == 0 {
			return fmt.Errorf("no-data: ungrounded original binding at %s", name)
		}
		catalog.Files[name] = originalFileRecord{SHA256: file.Digest, Size: file.Size, Bindings: sortedOriginalBindings(bindings)}
		for _, binding := range bindings {
			resolved := e.resolved[binding.Source]
			if resolved == nil || binding.Path == "" {
				return fmt.Errorf("no-data: unresolved original binding at %s", name)
			}
			catalog.Sources[binding.Source] = resolved.Source
		}
	}
	data, err := encodeOriginalsCatalog(catalog)
	if err != nil {
		return err
	}
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	properties := []cdx.Property{}
	if bom.Metadata.Properties != nil {
		for _, property := range *bom.Metadata.Properties {
			if property.Name != originalsProperty {
				properties = append(properties, property)
			}
		}
	}
	properties = append(properties, cdx.Property{Name: originalsProperty, Value: string(data)})
	bom.Metadata.Properties = &properties
	return nil
}
