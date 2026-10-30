package nativegate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const (
	materializedContextFile  = "context.json"
	materializedOriginalsDir = "originals"
)

// MaterializeBuildContextOptions carries what only the caller knows about the private
// build namespace the context is written for.
type MaterializeBuildContextOptions struct {
	// ContainerRoot is the absolute directory the host scratch appears at inside the
	// namespace. Every path the written context declares is below it.
	ContainerRoot string

	// Snapshots are the observed stage boundaries, oldest first. When they are given the
	// declaration must carry no imports of its own: the mapping is derived from the
	// declared source imports of those stages, each with the candidate receipt held in
	// memory, which is not every import the build performs. The last snapshot must be the
	// target the observed index was taken from.
	Snapshots []SourceSnapshot

	// WebpackSources asks for the private originals manifest beside the context. It
	// states the digests the imports were just proven against, so the Node collector
	// rehashes the sources a bundle consumed instead of reading the exported layouts.
	WebpackSources bool

	// GitOriginals are the Git-pinned Node distributions the caller verified, each
	// with the installed files it was found to serve. They are named in the same
	// private manifest, which is the only place the Node resolver may learn that a
	// Git-locked package has an original at all.
	GitOriginals []GitOriginal
}

// MaterializeBuildContext fills a prepared build context declaration with the original
// packages it pins and writes it where the compile and link helpers read it.
//
// The declaration is the caller's proof: subject, target platform, pinned packets and
// the declared import mapping are what the actual stage established, and nothing here
// derives them from the produced image, the host filesystem or a package name. Added are
// the OCI layout of each package, exported under ContainerRoot so that compilation never
// reaches a registry, and the proof that every imported path is a regular file the stage
// shipped whose bytes the original still serves.
//
// directory is a caller-owned empty host scratch mounted at ContainerRoot. The returned
// filename is the namespace path of the context file, whose host twin is the file of the
// same name directly in directory. A failure leaves nothing behind but the caller's own
// directory.
func MaterializeBuildContext(ctx context.Context, declaration *buildcontext.Context, observed *shippedscope.FileIndex, directory string, opts MaterializeBuildContextOptions) (string, error) {
	if declaration == nil {
		return "", fmt.Errorf("no-data: the build context declaration is missing")
	}
	if observed == nil || observed.Incomplete || observed.Files == nil {
		return "", fmt.Errorf("no-data: materializing a build context needs the complete observed file index of the target")
	}
	if err := namespacePath(opts.ContainerRoot); err != nil {
		return "", fmt.Errorf("container root %w", err)
	}
	if err := emptyScratch(directory); err != nil {
		return "", err
	}
	if err := checkDeclaredStructure(declaration, opts); err != nil {
		return "", err
	}

	resolved, indexes, err := resolveContextPackages(ctx, declaration)
	if err != nil {
		return "", err
	}
	if err := checkContextSubject(declaration, resolved, indexes); err != nil {
		return "", err
	}

	imports := declaration.Imports
	if len(opts.Snapshots) > 0 {
		if err := checkObservedTarget(opts.Snapshots, observed); err != nil {
			return "", err
		}
		imports, err = producerContextImports(ctx, opts.Snapshots, resolved, canonicalPackages(indexes))
		if err != nil {
			return "", err
		}
	}

	wanted, err := importedOriginals(declaration, imports, observed)
	if err != nil {
		return "", err
	}
	for i, pkg := range declaration.Packages {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := verifyOriginalFiles(ctx, resolved[indexes[i]].Original, wanted[i]); err != nil {
			return "", fmt.Errorf("package %d (%s): %w", i, pkg.Registry, err)
		}
	}

	materialized := *declaration
	materialized.Imports = imports
	materialized.Packages = slices.Clone(declaration.Packages)

	originals := filepath.Join(directory, materializedOriginalsDir)
	if err := os.Mkdir(originals, 0o755); err != nil {
		return "", err
	}
	exported, webpack := false, false
	defer func() {
		if !exported {
			_ = os.RemoveAll(originals)
			if webpack {
				_ = os.Remove(filepath.Join(directory, materializedWebpackFile))
			}
		}
	}()

	layouts := make(map[string]string, len(indexes))
	for i := range materialized.Packages {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		id := indexes[i]
		if _, done := layouts[id]; !done {
			name := originalLayoutName(id)
			if err := exportOriginalLayout(filepath.Join(originals, name), resolved[id]); err != nil {
				return "", fmt.Errorf("package %d (%s): %w", i, materialized.Packages[i].Registry, err)
			}
			layouts[id] = path.Join(opts.ContainerRoot, materializedOriginalsDir, name)
		}
		materialized.Packages[i].Layout = layouts[id]
	}

	// Encode validates the filled context, so nothing is written before the layouts, the
	// target and the subject are checked together.
	data, err := buildcontext.Encode(&materialized)
	if err != nil {
		return "", err
	}

	if opts.WebpackSources {
		manifest, err := webpackOriginalsManifest(imports, resolved, indexes, opts.GitOriginals)
		if err != nil {
			return "", err
		}
		if err := writeContext(filepath.Join(directory, materializedWebpackFile), manifest); err != nil {
			return "", err
		}
		webpack = true
	}
	if err := writeContext(filepath.Join(directory, materializedContextFile), data); err != nil {
		return "", err
	}
	exported = true

	return path.Join(opts.ContainerRoot, materializedContextFile), nil
}

// writeContext creates the file the helpers read and removes it again if it cannot be
// written in full, so that a half-written context is never left for them to find. The
// exclusive create keeps the removal to the file this call made.
func writeContext(filename string, data []byte) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err = errors.Join(err, file.Close()); err != nil {
		return errors.Join(err, os.Remove(filename))
	}

	return nil
}

// checkDeclaredStructure refuses what the declaration itself already gets wrong, before
// anything is fetched. The public codec does the checking, on a copy whose layouts carry
// the placeholder materialization has yet to replace.
func checkDeclaredStructure(declaration *buildcontext.Context, opts MaterializeBuildContextOptions) error {
	if len(opts.Snapshots) > 0 && len(declaration.Imports) > 0 {
		return fmt.Errorf("invalid: imports derived from the stage snapshots leave no room for %d declared ones", len(declaration.Imports))
	}
	if len(opts.GitOriginals) > 0 && !opts.WebpackSources {
		return fmt.Errorf("invalid: %d verified Git originals have no manifest to be named in", len(opts.GitOriginals))
	}

	pending := *declaration
	pending.Packages = slices.Clone(declaration.Packages)
	for i := range pending.Packages {
		pending.Packages[i].Layout = opts.ContainerRoot
	}

	return buildcontext.Validate(&pending)
}

// resolveContextPackages fetches and verifies the original behind every declared
// package, once per pinned identity: entries that differ only in how the receipt spelled
// one package share a fetch and an exported layout. It returns the originals by identity
// and, per declared package, the identity it pins.
func resolveContextPackages(ctx context.Context, declaration *buildcontext.Context) (map[string]*resolvedSource, []string, error) {
	// Only the resolution cache of the shared evidence is used here; matching a
	// snapshot is not this caller's business.
	evidence := &sourceEvidence{resolved: map[string]*resolvedSource{}}
	indexes := make([]string, len(declaration.Packages))
	for i, pkg := range declaration.Packages {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		resolved, err := evidence.resolve(ctx, sources.Source{Registry: pkg.Registry, Packet: pkg.Packet, Platform: pkg.Platform})
		if err != nil {
			return nil, nil, fmt.Errorf("package %d (%s): %w", i, pkg.Registry, err)
		}
		indexes[i] = resolved.ID
	}

	return evidence.resolved, indexes, nil
}

// checkContextSubject applies the consumer's rule for a package subject: it must name
// one of the pinned packages by source and version, and never the produced image.
func checkContextSubject(declaration *buildcontext.Context, resolved map[string]*resolvedSource, indexes []string) error {
	subject := declaration.Subject
	if subject.Source.Kind != "pm" {
		return nil
	}
	for i, pkg := range declaration.Packages {
		metadata := resolved[indexes[i]].Package
		if subject.Source.Locator == pkg.Registry && subject.Source.Checksum == metadata.Digest &&
			subject.Version == metadata.Version && subject.Name == metadata.Name {
			return nil
		}
	}

	return fmt.Errorf("%s: pm subject has no matching pinned package identity", subject.Name)
}

// importedOriginals binds every import to the bytes the stage shipped at it, grouped by
// the package expected to serve them. The whole mapping is checked before any of it is
// read.
func importedOriginals(declaration *buildcontext.Context, imports []buildcontext.Import, observed *shippedscope.FileIndex) ([]map[string]shippedscope.File, error) {
	wanted := make([]map[string]shippedscope.File, len(declaration.Packages))
	seen := map[string]bool{}
	for _, mapping := range imports {
		if err := namespacePath(mapping.Path); err != nil {
			return nil, fmt.Errorf("import %w", err)
		}
		if mapping.Package == nil || *mapping.Package < 0 || *mapping.Package >= len(declaration.Packages) {
			return nil, fmt.Errorf("%s: invalid or missing package index", mapping.Path)
		}
		if err := originalPath(mapping.OriginalPath); err != nil {
			return nil, fmt.Errorf("%s: %w", mapping.Path, err)
		}
		if seen[mapping.Path] {
			return nil, fmt.Errorf("%s: ambiguous import mapping", mapping.Path)
		}
		seen[mapping.Path] = true

		file, shipped := observed.Files[mapping.Path]
		if !shipped {
			if _, symlink := observed.Symlinks[mapping.Path]; symlink {
				return nil, fmt.Errorf("%s: the stage shipped a symlink here, not the physical file an import maps", mapping.Path)
			}

			return nil, fmt.Errorf("%s: the stage shipped no regular file here", mapping.Path)
		}

		index := *mapping.Package
		if wanted[index] == nil {
			wanted[index] = map[string]shippedscope.File{}
		}
		if held, claimed := wanted[index][mapping.OriginalPath]; claimed && held != file {
			return nil, fmt.Errorf("%s: package %d original %q is claimed for different bytes", mapping.Path, index, mapping.OriginalPath)
		}
		wanted[index][mapping.OriginalPath] = file
	}

	return wanted, nil
}

// canonicalPackages names one declared package per pinned identity. Entries pinning one
// original are interchangeable — resolution refuses conflicting packet metadata for one
// identity — so the first of them stands for the rest.
func canonicalPackages(indexes []string) map[string]int {
	canonical := make(map[string]int, len(indexes))
	for position, id := range indexes {
		if _, known := canonical[id]; !known {
			canonical[id] = position
		}
	}

	return canonical
}

// checkObservedTarget keeps the derived imports bound to the index they are verified
// against: the last stage boundary is the target, not a reconstruction of it.
func checkObservedTarget(snapshots []SourceSnapshot, observed *shippedscope.FileIndex) error {
	last := snapshots[len(snapshots)-1]
	if last.Index == nil || last.Index.Incomplete {
		return fmt.Errorf("no-data: stage %q holds no complete snapshot index", last.Stage)
	}
	if !maps.Equal(last.Index.Files, observed.Files) || !maps.Equal(last.Index.Symlinks, observed.Symlinks) {
		return fmt.Errorf("no-data: stage %q is not the target the observed index was taken from", last.Stage)
	}

	return nil
}

// exportOriginalLayout writes the pinned manifest and the blobs it references. The
// packet digest stays the layout's own descriptor, because that is what the consumer
// looks the package up by, so a pinned index costs its whole graph rather than being
// replaced by the child platform selection resolved to.
func exportOriginalLayout(directory string, resolved *resolvedSource) error {
	if resolved.Root.Index == nil && resolved.Root.Image == nil {
		return fmt.Errorf("no-data: original %s carries no verified pinned manifest", resolved.ID)
	}

	target, err := layout.Write(directory, empty.Index)
	if err != nil {
		return err
	}
	if resolved.Root.Index != nil {
		return target.AppendIndex(resolved.Root.Index)
	}

	return target.AppendImage(resolved.Root.Image)
}

// originalLayoutName is a file name for an original identity, which carries a registry
// path and a digest.
func originalLayoutName(id string) string {
	return strings.TrimPrefix(digest([]byte(id)), "sha256:")
}

func emptyScratch(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s: a build context is materialized into an empty caller-owned directory", directory)
	}

	return nil
}

// namespacePath checks what the private namespace will read, so no host spelling reaches
// the written context.
func namespacePath(filename string) error {
	if !path.IsAbs(filename) || path.Clean(filename) != filename || strings.ContainsRune(filename, '\x00') {
		return fmt.Errorf("path %q: expected a clean absolute path", filename)
	}

	return nil
}

func originalPath(name string) error {
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("invalid original package path %q", name)
	}

	return nil
}
