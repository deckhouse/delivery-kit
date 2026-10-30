package nativegate

import (
	"cmp"
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
	// Lifecycle names, per component, the install hooks its own manifest defines. It
	// is why a file the component holds may be absent: what a hook wrote is not the
	// original's bytes, and the reader attributes no path it does not list.
	Lifecycle []webpackOriginalLifecycle `json:"lifecycle,omitempty"`
}

// webpackOriginalFile carries the expected digest of an imported path, not a claim that
// the bundle used it: selecting the consumed files is the collector's business.
type webpackOriginalFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Component string `json:"component"`
}

type webpackOriginalLifecycle struct {
	Component string   `json:"component"`
	Hooks     []string `json:"hooks"`
}

// webpackOriginalsManifest states each import as the original entry it was just verified
// against, under the pm identity that serves it. The digest is the original's own, never
// the observed file's: the observed bytes are evidence only because the verification
// this follows found them equal.
func webpackOriginalsManifest(imports []buildcontext.Import, resolved map[string]*resolvedSource, indexes []string, gitOriginals []GitOriginal) (webpackOriginals, error) {
	manifest := webpackOriginals{Version: 1, Components: []shared.BuildComponent{}, Files: []webpackOriginalFile{}}
	held := map[string]webpackOriginalFile{}
	for _, mapping := range imports {
		source := resolved[indexes[*mapping.Package]]
		entry, err := source.Original.Lookup(mapping.OriginalPath)
		if err != nil {
			return webpackOriginals{}, fmt.Errorf("%s: %w", mapping.Path, err)
		}
		if entry.SHA256 == "" {
			return webpackOriginals{}, fmt.Errorf("%s: the original serves no digest for %q", mapping.Path, mapping.OriginalPath)
		}
		file := webpackOriginalFile{Path: mapping.Path, SHA256: entry.SHA256, Component: source.ID}
		if claimed, taken := held[mapping.Path]; taken && claimed != file {
			return webpackOriginals{}, fmt.Errorf("%s: claimed for a second original identity or digest", mapping.Path)
		}
		held[mapping.Path] = file

		if !slices.ContainsFunc(manifest.Components, func(component shared.BuildComponent) bool { return component.ID == source.ID }) {
			manifest.Components = append(manifest.Components, shared.BuildComponent{
				ID: source.ID, Name: source.Package.Name, Version: source.Package.Version,
				Source: shared.BuildSource{Kind: "pm", Locator: source.Source.Registry, Checksum: source.Package.Digest},
			})
		}
	}

	for _, original := range gitOriginals {
		if slices.ContainsFunc(manifest.Components, func(component shared.BuildComponent) bool { return component.ID == original.Component.ID }) {
			return webpackOriginals{}, fmt.Errorf("%s: a second original claims the identity %s", original.Component.Name, original.Component.ID)
		}
		manifest.Components = append(manifest.Components, original.Component)
		if len(original.Lifecycle) > 0 {
			manifest.Lifecycle = append(manifest.Lifecycle, webpackOriginalLifecycle{Component: original.Component.ID, Hooks: original.Lifecycle})
		}
		for _, file := range original.Files {
			if err := namespacePath(file.Path); err != nil {
				return webpackOriginals{}, fmt.Errorf("%s: installed %w", original.Component.Name, err)
			}
			entry := webpackOriginalFile{Path: file.Path, SHA256: file.SHA256, Component: original.Component.ID}
			if claimed, taken := held[file.Path]; taken && claimed != entry {
				return webpackOriginals{}, fmt.Errorf("%s: claimed for a second original identity or digest", file.Path)
			}
			held[file.Path] = entry
		}
	}

	for _, path := range slices.Sorted(maps.Keys(held)) {
		manifest.Files = append(manifest.Files, held[path])
	}
	slices.SortFunc(manifest.Components, func(a, b shared.BuildComponent) int { return cmp.Compare(a.ID, b.ID) })

	return manifest, nil
}
