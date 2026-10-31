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
func producerContextImports(ctx context.Context, snapshots []SourceSnapshot, packages map[string]*resolvedSource, indexes map[string]int, installed []InstalledPacket) ([]buildcontext.Import, error) {
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

	index, matches, seeded := snapshots[0].Index, make(originalMatches), 0
	identities := make([]string, len(installed))
	for position, snapshot := range snapshots[1:] {
		next, err := carriedContextMatches(index, matches, snapshot)
		if err != nil {
			return nil, err
		}
		if len(installed) > 0 && snapshot.Stage != packageInstallStage && !declaredImport(snapshot) {
			// The seeded bindings stand on the install metadata of one observed
			// boundary, so every other boundary has to have installed nothing.
			if err := checkInstallBoundary(snapshots[position], snapshot); err != nil {
				return nil, err
			}
		}
		if len(installed) > 0 && snapshot.Stage == packageInstallStage {
			opened, err := installedContextMatches(ctx, snapshot, installed, packages, identities)
			if err != nil {
				return nil, err
			}
			for destination, bindings := range opened {
				next[destination] = sortedOriginalBindings(append(next[destination], bindings...))
			}
			seeded++
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
	if len(installed) > 0 && seeded != 1 {
		return nil, fmt.Errorf("no-data: %d observed package install boundaries carry the %d declared installed packets", seeded, len(installed))
	}

	imports, err := contextImports(index, matches, indexes)
	if err != nil {
		return nil, err
	}

	return imports, checkInstalledPacketFiles(imports, installed, identities, indexes)
}

// Only a path such a stage keeps byte for byte keeps the binding an earlier stage
// established, and nothing it happens to hold takes a binding over from equal bytes
// elsewhere.
func carriedContextMatches(index *shippedscope.FileIndex, matches originalMatches, snapshot SourceSnapshot) (originalMatches, error) {
	if installsRatherThanBuilds(snapshot.Stage) {
		return retainedOriginalMatches(index, matches, snapshot.Index), nil
	}

	return carryOriginalMatches(index, matches, snapshot.Index)
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

// InstalledPacket is one pm packet a stage declares it installed, and the installed
// files of it the producer context is to be built on. The identity is the producer's
// claim and nothing else: which receipt entry it names is settled by the install receipt
// the stage actually carries, and whether those files are that packet's by the pinned
// Packet digest and by the installed bytes.
type InstalledPacket struct {
	Name     string
	Version  string
	Type     string
	Platform string
	// Files are the installed paths the context is held to. Each of them has to stand
	// in the built stage as bytes the packet still serves, or the whole context is
	// refused: a tool a build is held against is no evidence once it is no longer the
	// tool the packet delivered.
	Files []string
}

// installedContextMatches binds what the install boundary holds of each declared packet.
// The receipt selects the one candidate entry, its pinned Packet digest names an original
// the context already declares, and only installed bytes that original still serves at the
// path it serves them under are bound. identities takes the resolved identity of each
// declared packet, in the order they were declared.
func installedContextMatches(ctx context.Context, snapshot SourceSnapshot, installed []InstalledPacket, packages map[string]*resolvedSource, identities []string) (originalMatches, error) {
	matches := make(originalMatches)
	for i, declared := range installed {
		source, err := SelectInstalledPacket(snapshot.Receipt, declared)
		if err != nil {
			return nil, err
		}
		id, err := receiptSourceID(source)
		if err != nil {
			return nil, err
		}
		resolved, exists := packages[id]
		if !exists {
			return nil, fmt.Errorf("invalid: the context declares no package for the installed packet %s %s", declared.Name, declared.Version)
		}
		if err := sameSourcePacket(source, resolved.Source); err != nil {
			return nil, fmt.Errorf("invalid: installed packet %s %s: %w", declared.Name, declared.Version, err)
		}
		identities[i] = id
		opened, err := matchSnapshotOriginals(ctx, snapshot.Index, map[string]*original.OriginalPackage{id: resolved.Original})
		if err != nil {
			return nil, err
		}
		for destination, bindings := range opened {
			matches[destination] = sortedOriginalBindings(append(matches[destination], bindings...))
		}
	}

	return matches, nil
}

// SelectInstalledPacket names the one entry of an install receipt that is the declared
// packet identity. A receipt naming none of it opened no such packet, and a receipt
// naming it more than once leaves a choice between candidates that this does not make.
func SelectInstalledPacket(receipt *sources.Receipt, declared InstalledPacket) (sources.Source, error) {
	if receipt == nil {
		return sources.Source{}, fmt.Errorf("no-data: the install boundary carries no package source receipt for %s %s", declared.Name, declared.Version)
	}
	var found []sources.Source
	for _, source := range receipt.Sources {
		metadata, err := readSourcePackage(source)
		if err != nil {
			return sources.Source{}, err
		}
		if metadata.Name != declared.Name || metadata.Version != declared.Version || metadata.Type != declared.Type {
			continue
		}
		if source.Platform != declared.Platform || !slices.Contains(metadata.Arch, declared.Platform) {
			continue
		}
		found = append(found, source)
	}
	if len(found) != 1 {
		return sources.Source{}, fmt.Errorf("no-data: %d receipt entries open the %s packet %s %s for %s, need exactly one", len(found), declared.Type, declared.Name, declared.Version, declared.Platform)
	}

	return found[0], nil
}

// checkInstalledPacketFiles holds the context to the files it was declared on: each of
// them is an import of that very packet here, or the context is refused rather than
// built on what is left of a tool.
func checkInstalledPacketFiles(imports []buildcontext.Import, installed []InstalledPacket, identities []string, indexes map[string]int) error {
	for i, declared := range installed {
		position, known := indexes[identities[i]]
		if !known {
			return fmt.Errorf("invalid: no context package for the installed packet %s %s", declared.Name, declared.Version)
		}
		for _, name := range declared.Files {
			// The packet serves a declared file at the path it stands at. Another
			// file of the same packet that happens to hold those bytes is not it.
			served := strings.TrimPrefix(name, "/")
			if !slices.ContainsFunc(imports, func(mapping buildcontext.Import) bool {
				return mapping.Path == name && mapping.OriginalPath == served && mapping.Package != nil && *mapping.Package == position
			}) {
				return fmt.Errorf("no-data: %s does not stand in the build as bytes the %s packet %s %s still serves", name, declared.Type, declared.Name, declared.Version)
			}
		}
	}

	return nil
}
