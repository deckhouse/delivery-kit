package nativegate

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
)

const materializedWebpackFile = "webpack-originals.json"

// webpackOriginals names, for the imports of one materialized context, the bytes their
// original is pinned to serve. It is private to this writer and the Node collector that
// reads it beside the context: the collector rehashes what the bundle consumed and finds
// the primary source here, so it needs neither the packet nor the original layout.
type webpackOriginals struct {
	Version    int                     `json:"version"`
	Components []shared.BuildComponent `json:"components"`
	Files      []webpackOriginalFile   `json:"files"`
}

// webpackOriginalFile carries the expected digest of an imported path, not a claim that
// the bundle used it: selecting the consumed files is the collector's business.
type webpackOriginalFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Component string `json:"component"`
}

// webpackOriginalsManifest states each import as the original entry it was just verified
// against, under the pm identity that serves it. The digest is the original's own, never
// the observed file's: the observed bytes are evidence only because the verification
// this follows found them equal.
func webpackOriginalsManifest(imports []buildcontext.Import, resolved map[string]*resolvedSource, indexes []string) ([]byte, error) {
	manifest := webpackOriginals{Version: 1, Components: []shared.BuildComponent{}, Files: []webpackOriginalFile{}}
	held := map[string]webpackOriginalFile{}
	for _, mapping := range imports {
		source := resolved[indexes[*mapping.Package]]
		entry, err := source.Original.Lookup(mapping.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", mapping.Path, err)
		}
		if entry.SHA256 == "" {
			return nil, fmt.Errorf("%s: the original serves no digest for %q", mapping.Path, mapping.OriginalPath)
		}
		file := webpackOriginalFile{Path: mapping.Path, SHA256: entry.SHA256, Component: source.ID}
		if claimed, taken := held[mapping.Path]; taken && claimed != file {
			return nil, fmt.Errorf("%s: claimed for a second original identity or digest", mapping.Path)
		}
		held[mapping.Path] = file

		if !slices.ContainsFunc(manifest.Components, func(component shared.BuildComponent) bool { return component.ID == source.ID }) {
			manifest.Components = append(manifest.Components, shared.BuildComponent{
				ID: source.ID, Name: source.Package.Name, Version: source.Package.Version,
				Source: shared.BuildSource{Kind: "pm", Locator: source.Source.Registry, Checksum: source.Package.Digest},
			})
		}
	}

	for _, path := range slices.Sorted(maps.Keys(held)) {
		manifest.Files = append(manifest.Files, held[path])
	}
	slices.SortFunc(manifest.Components, func(a, b shared.BuildComponent) int { return cmp.Compare(a.ID, b.ID) })

	return json.Marshal(manifest)
}
