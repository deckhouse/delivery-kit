package nativegate

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func ProjectImageOriginals(ctx context.Context, originals []Original, source, before, after *shippedscope.FileIndex, scope ImportScope) ([]Original, error) {
	matches := map[string]Original{}
	for _, original := range originals {
		matches[original.Path] = original
	}
	paths := map[string]bool{}
	for name := range matches {
		paths[name] = true
	}
	projected, err := projectImportPaths(ctx, source, before, after, scope, paths)
	if err != nil {
		return nil, err
	}
	var result []Original
	for _, name := range slices.Sorted(maps.Keys(projected)) {
		original := matches[name]
		original.Path = projected[name]
		result = append(result, original)
	}
	return result, nil
}

func projectImportPaths(ctx context.Context, source, before, after *shippedscope.FileIndex, scope ImportScope, paths map[string]bool) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source.Incomplete || before.Incomplete || after.Incomplete {
		return nil, fmt.Errorf("%s: no-data: incomplete import filesystem", scope.FromPath)
	}
	from, err := importSourcePath(source, scope.FromPath)
	if err != nil {
		return nil, err
	}
	if _, link := source.Symlinks[from]; link {
		return nil, fmt.Errorf("%s: unsupported symlink as import source", scope.FromPath)
	}
	to, err := importDestinationPath(before, after, scope.ToPath)
	if err != nil {
		return nil, err
	}
	carries, err := importScopeCarries(scope, from)
	if err != nil {
		return nil, err
	}
	return projectedImportPaths(source, paths, before, after, from, to, carries)
}

func ProjectImageSymlinks(ctx context.Context, source, before, after *shippedscope.FileIndex, scope ImportScope) (map[string]string, error) {
	paths := map[string]bool{}
	for name := range source.Symlinks {
		paths[name] = true
	}
	projected, err := projectImportPaths(ctx, source, before, after, scope, paths)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for original, destination := range projected {
		result[destination] = source.Symlinks[original]
	}
	return result, nil
}
