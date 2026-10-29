package nativegate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// Initial snapshots match original paths; later shell snapshots must use scoped carry.
func matchSnapshotOriginals(ctx context.Context, index *shippedscope.FileIndex, originals map[string]*original.OriginalPackage) (originalMatches, error) {
	if index == nil || index.Incomplete {
		return nil, fmt.Errorf("no-data: snapshot index cannot bind originals")
	}

	matches := make(originalMatches)
	for _, source := range slices.Sorted(maps.Keys(originals)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		pkg := originals[source]
		if pkg == nil || !pkg.Complete() {
			return nil, fmt.Errorf("no-data: original %q holds no verified view", source)
		}

		wanted := make(map[string]shippedscope.File)
		for _, entry := range pkg.Entries() {
			path := "/" + entry.Path
			file, ok := index.Files[path]
			if !ok {
				continue
			}
			if entry.Err != nil {
				return nil, fmt.Errorf("original %q at %q: %w", source, entry.Path, entry.Err)
			}
			if entry.SHA256 == "" || entry.SHA256 != file.Digest {
				continue
			}

			wanted[entry.Path] = file
		}

		if err := verifyOriginalFiles(ctx, pkg, wanted); err != nil {
			return nil, fmt.Errorf("original %q: %w", source, err)
		}

		for _, path := range slices.Sorted(maps.Keys(wanted)) {
			matches["/"+path] = append(matches["/"+path], originalBinding{Source: source, Path: path})
		}
	}

	for path, bindings := range matches {
		matches[path] = sortedOriginalBindings(bindings)
	}

	return matches, nil
}

// verifyOriginalFiles reads the bytes behind expected, keyed by package-relative path and
// holding the snapshot's digest and size, and reports whether the package still serves them.
// It streams each layer once instead of fetching the blob per file, so an SDK-sized package
// costs its own size rather than its size times its file count.
func verifyOriginalFiles(ctx context.Context, pkg *original.OriginalPackage, expected map[string]shippedscope.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pkg == nil || !pkg.Complete() {
		return fmt.Errorf("no-data: original holds no verified view")
	}
	if len(expected) == 0 {
		return nil
	}

	for _, path := range slices.Sorted(maps.Keys(expected)) {
		entry, err := pkg.Lookup(path)
		if err != nil {
			return fmt.Errorf("at %q: %w", path, err)
		}
		if entry.SHA256 == "" || entry.SHA256 != expected[path].Digest {
			return fmt.Errorf("at %q: the original no longer holds the expected bytes", path)
		}
	}

	observed := make(map[string]bool, len(expected))
	// Draining each entry to EOF finishes the canonical reader's hash check.
	complete, fileErrors, traversalErr := pkg.WalkFiles(func(entries []original.OriginalEntry, body io.Reader) error {
		if err := ctx.Err(); err != nil {
			_, drained := io.Copy(io.Discard, body)
			return errors.Join(err, drained)
		}

		read, err := io.Copy(io.Discard, body)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			file, ok := expected[entry.Path]
			if !ok {
				continue
			}
			observed[entry.Path] = true
			if read != file.Size {
				return fmt.Errorf("%d bytes against %d in the snapshot", read, file.Size)
			}
		}

		return nil
	})

	var failures []error
	// Errors on paths the snapshot never asked for are not this caller's: an original
	// commonly links out into a package it was split from. The contract is to check all
	// three results for the selected paths.
	for _, path := range slices.Sorted(maps.Keys(fileErrors)) {
		if _, wanted := expected[path]; !wanted {
			continue
		}
		failures = append(failures, fmt.Errorf("at %q: %w", path, fileErrors[path]))
	}
	if traversalErr != nil {
		failures = append(failures, traversalErr)
	}
	if !complete {
		failures = append(failures, fmt.Errorf("no-data: the original could not be walked in full"))
	}
	for _, path := range slices.Sorted(maps.Keys(expected)) {
		if !observed[path] {
			failures = append(failures, fmt.Errorf("at %q: the original served no bytes", path))
		}
	}

	return errors.Join(failures...)
}
