package nativegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// Snapshot Imports must contain only the declared source-image imports, with their
// verified RESULT candidates. Unrelated imports remain in the filesystem observations.
func producerContextImports(ctx context.Context, snapshots []SourceSnapshot, packages map[string]*resolvedSource, indexes map[string]int) ([]buildcontext.Import, error) {
	if len(snapshots) == 0 {
		return nil, fmt.Errorf("no-data: the producer context needs the actual stage snapshots")
	}
	for _, snapshot := range snapshots {
		if snapshot.Index == nil || snapshot.Index.Incomplete {
			return nil, fmt.Errorf("no-data: incomplete source snapshot for %s", snapshot.Stage)
		}
	}
	if len(snapshots[0].Imports) != 0 {
		return nil, fmt.Errorf("no-data: the base snapshot %s precedes no stage an import could be projected onto", snapshots[0].Stage)
	}

	index, matches := snapshots[0].Index, make(originalMatches)
	for _, snapshot := range snapshots[1:] {
		next, err := carriedContextMatches(index, matches, snapshot)
		if err != nil {
			return nil, err
		}
		for _, imported := range snapshot.Imports {
			carried, err := importedContextMatches(ctx, imported, packages, index, snapshot.Index)
			if err != nil {
				return nil, err
			}
			// Equal bytes from another import make one more candidate origin, not the chosen one.
			for destination, bindings := range carried {
				next[destination] = sortedOriginalBindings(append(next[destination], bindings...))
			}
		}
		index, matches = snapshot.Index, next
	}

	return contextImports(index, matches, indexes)
}

// A dependency stage holds whatever it imports plus its own base; only a path it keeps
// byte for byte keeps the binding an earlier stage established, and nothing it happens to
// hold takes a binding over from equal bytes elsewhere.
func carriedContextMatches(index *shippedscope.FileIndex, matches originalMatches, snapshot SourceSnapshot) (originalMatches, error) {
	if !strings.HasPrefix(snapshot.Stage, "dependencies") {
		return carryOriginalMatches(index, matches, snapshot.Index)
	}

	kept := make(originalMatches)
	for held, bindings := range matches {
		if file, exists := snapshot.Index.Files[held]; exists && file == index.Files[held] {
			kept[held] = slices.Clone(bindings)
		}
	}

	return kept, nil
}

func importedContextMatches(ctx context.Context, imported SourceImport, packages map[string]*resolvedSource, before, after *shippedscope.FileIndex) (originalMatches, error) {
	if imported.Index == nil || imported.Index.Incomplete {
		return nil, fmt.Errorf("no-data: missing imported source snapshot")
	}
	declared, err := declaredImportOriginals(imported.Receipt, packages)
	if err != nil {
		return nil, err
	}
	matches, err := matchSnapshotOriginals(ctx, imported.Index, declared)
	if err != nil {
		return nil, err
	}

	return importOriginalMatches(ctx, imported.Index, matches, before, after, imported.Scope)
}

// declaredImportOriginals keeps the originals of the source image that the context
// declares, by the identity each receipt entry pins on its own. An entry naming anything
// else is not an input of this context and binds nothing, and two spellings of one
// declared identity are a conflict rather than a choice.
func declaredImportOriginals(receipt *sources.Receipt, packages map[string]*resolvedSource) (map[string]*original.OriginalPackage, error) {
	if receipt == nil {
		return nil, fmt.Errorf("no-data: the imported source image carries no original source receipt")
	}

	declared := make(map[string]*original.OriginalPackage)
	for _, source := range receipt.Sources {
		id, err := receiptSourceID(source)
		if err != nil {
			return nil, err
		}
		resolved, ok := packages[id]
		if !ok {
			continue
		}
		if err := sameSourcePacket(source, resolved.Source); err != nil {
			return nil, fmt.Errorf("invalid: original source %s: %w", id, err)
		}
		declared[id] = resolved.Original
	}

	return declared, nil
}

func receiptSourceID(source sources.Source) (string, error) {
	identity, err := parseOriginalSourceIdentity(source)
	if err != nil {
		return "", err
	}
	return originalSourceID(identity.Repository.Name(), identity.Pin, identity.Platform), nil
}

// Raw Packet spelling is preserved; only whitespace is insignificant for reuse.
func sameSourcePacket(source, declared sources.Source) error {
	var found, expected bytes.Buffer
	if err := json.Compact(&found, source.Packet); err != nil {
		return err
	}
	if err := json.Compact(&expected, declared.Packet); err != nil {
		return err
	}
	if !bytes.Equal(found.Bytes(), expected.Bytes()) {
		return fmt.Errorf("conflicting Packet metadata")
	}

	return nil
}

func contextImports(index *shippedscope.FileIndex, matches originalMatches, indexes map[string]int) ([]buildcontext.Import, error) {
	imports := make([]buildcontext.Import, 0, len(matches))
	for _, destination := range slices.Sorted(maps.Keys(matches)) {
		if _, exists := index.Files[destination]; !exists {
			return nil, fmt.Errorf("no-data: the build no longer holds an imported original at %s", destination)
		}
		binding, err := uniqueOriginalBinding(matches[destination])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", destination, err)
		}
		position, exists := indexes[binding.Source]
		if !exists {
			return nil, fmt.Errorf("invalid: no context package for original source %s at %s", binding.Source, destination)
		}
		imports = append(imports, buildcontext.Import{Path: destination, Package: &position, OriginalPath: binding.Path})
	}

	return imports, nil
}
