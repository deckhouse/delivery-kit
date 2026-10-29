package nativegate

import (
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// assetProjectionSource is the placeholder original the projection carries through the
// import, so that a path the copy landed can be read back to the source path it came from.
const assetProjectionSource = "asset"

// ProjectImportedDirectory answers at which path of the target image a directory of the
// import source lands. The answer is derived from the import alone: it holds whether or
// not the copy carried any file of that directory, so an asset root stays placed when the
// import filters or the stage left it empty.
//
// The directory is named as the source image records it — a clean rooted path of a real
// directory, not a path reached through a symlink — and must lie within the import source.
// Only a directory import places an asset root; anything else is no-data.
func ProjectImportedDirectory(ctx context.Context, source, before, after *shippedscope.FileIndex, scope ImportScope, directory string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	from, to, err := importedAssetRoots(source, before, after, scope)
	if err != nil {
		return "", err
	}
	if rootedImportPath(directory) != directory {
		return "", fmt.Errorf("asset directory %q is not a clean rooted path", directory)
	}
	if _, ok := source.Directories[directory]; !ok {
		return "", fmt.Errorf("no-data: asset directory %q is not a directory of the import source image", directory)
	}
	if resolved, err := resolvePath(&filesystem{index: source}, directory); err != nil || resolved != directory {
		return "", fmt.Errorf("no-data: asset directory %q stands behind symlinks of the source image", directory)
	}

	relative, under := pathUnder(from, directory)
	if directory != from && !under {
		return "", fmt.Errorf("no-data: asset directory %q is outside import source %q", directory, scope.FromPath)
	}

	// The copy lands the contents of the import source in the destination itself.
	return path.Join(to, relative), nil
}

// ProjectImportedFiles answers where the named files of the import source land in the
// target image, as source path to target path. A file the copy left behind, or one whose
// landed bytes the stage then changed, is absent from the answer: equal bytes the target
// holds for another reason bind nothing.
//
// Every name must be a regular file the source image holds; a name it does not is an
// error rather than a silently missing mapping.
func ProjectImportedFiles(ctx context.Context, source, before, after *shippedscope.FileIndex, scope ImportScope, files []string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, _, err := importedAssetRoots(source, before, after, scope); err != nil {
		return nil, err
	}

	asked := make(originalMatches, len(files))
	for _, file := range files {
		asked[file] = []originalBinding{{Source: assetProjectionSource, Path: strings.TrimPrefix(file, "/")}}
	}
	imported, err := importOriginalMatches(ctx, source, asked, before, after, scope)
	if err != nil {
		return nil, err
	}

	projected := make(map[string]string, len(imported))
	for _, destination := range slices.Sorted(maps.Keys(imported)) {
		binding, err := uniqueOriginalBinding(imported[destination])
		if err != nil {
			return nil, fmt.Errorf("no-data: the import lands %q: %w", destination, err)
		}
		file := "/" + binding.Path
		if _, ok := asked[file]; !ok {
			return nil, fmt.Errorf("no-data: the import lands %q with an original this projection did not place", destination)
		}
		if landed, ok := projected[file]; ok {
			return nil, fmt.Errorf("no-data: the import lands %q on both %q and %q", file, landed, destination)
		}
		projected[file] = destination
	}

	return projected, nil
}

// importedAssetRoots reads the source and destination roots of an asset import off the
// snapshots the stage was built from. Only a directory import is read here: a file import
// places no root to hang an asset tree on, and a symlinked import source travels as the
// link, leaving the tree it names where it was.
func importedAssetRoots(source, before, after *shippedscope.FileIndex, scope ImportScope) (string, string, error) {
	if source == nil || before == nil || after == nil {
		return "", "", fmt.Errorf("no-data: projecting an asset import needs the source and both target snapshots")
	}
	if source.Incomplete || before.Incomplete || after.Incomplete {
		return "", "", fmt.Errorf("no-data: an incomplete snapshot cannot place an asset import")
	}
	if source.Directories == nil || before.Directories == nil || after.Directories == nil {
		return "", "", fmt.Errorf("no-data: projecting an asset import needs directory facts")
	}

	from, err := importSourcePath(source, scope.FromPath)
	if err != nil {
		return "", "", err
	}
	// The backend and its filters have to be readable even when no file is asked for.
	if _, err := importScopeCarries(scope, from); err != nil {
		return "", "", err
	}
	if _, ok := source.Symlinks[from]; ok {
		return "", "", fmt.Errorf("no-data: import source %q is a symlink, so the tree it names does not land at the destination", scope.FromPath)
	}
	if _, ok := source.Directories[from]; !ok {
		return "", "", fmt.Errorf("no-data: import source %q is not a directory of the source image", scope.FromPath)
	}

	to, err := importDestinationPath(before, after, scope.ToPath)
	if err != nil {
		return "", "", err
	}

	return from, to, nil
}
