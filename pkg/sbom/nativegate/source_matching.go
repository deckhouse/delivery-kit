package nativegate

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// originalBinding identifies matching original bytes, not the origin of a shell copy.
type originalBinding struct {
	Source string `json:"source"`
	Path   string `json:"path"`
}

type originalMatches map[string][]originalBinding

func carryOriginalMatches(before *shippedscope.FileIndex, matches originalMatches, after *shippedscope.FileIndex) (originalMatches, error) {
	if before == nil || after == nil {
		return nil, fmt.Errorf("no-data: original matching needs both snapshots")
	}
	if before.Incomplete || after.Incomplete {
		return nil, fmt.Errorf("no-data: incomplete snapshot cannot carry original matches")
	}

	byFile := make(map[shippedscope.File][]originalBinding)
	for _, path := range slices.Sorted(maps.Keys(matches)) {
		file, ok := before.Files[path]
		if !ok {
			return nil, fmt.Errorf("original match %q is outside the indexed snapshot", path)
		}
		bindings := matches[path]
		if len(bindings) == 0 {
			return nil, fmt.Errorf("original match %q carries no binding", path)
		}
		for _, binding := range bindings {
			if binding.Source == "" || binding.Path == "" {
				return nil, fmt.Errorf("original match %q carries an incomplete binding", path)
			}
			byFile[file] = append(byFile[file], binding)
		}
	}

	carried := make(originalMatches)
	for path, file := range after.Files {
		// Retained evidence is not replaced by a guess among other equal-byte paths.
		if kept, ok := matches[path]; ok && before.Files[path] == file {
			carried[path] = sortedOriginalBindings(kept)

			continue
		}
		if alternatives, ok := byFile[file]; ok {
			carried[path] = sortedOriginalBindings(alternatives)
		}
	}

	return carried, nil
}

func uniqueOriginalBinding(bindings []originalBinding) (originalBinding, error) {
	unique := sortedOriginalBindings(bindings)
	if len(unique) != 1 {
		return originalBinding{}, fmt.Errorf("no-data: %d original bindings, need exactly one", len(unique))
	}
	if unique[0].Source == "" || unique[0].Path == "" {
		return originalBinding{}, fmt.Errorf("no-data: the one original binding names no usable original")
	}

	return unique[0], nil
}

func sortedOriginalBindings(bindings []originalBinding) []originalBinding {
	sorted := slices.Clone(bindings)
	slices.SortFunc(sorted, func(a, b originalBinding) int {
		if a.Source != b.Source {
			return cmp.Compare(a.Source, b.Source)
		}

		return cmp.Compare(a.Path, b.Path)
	})

	return slices.Compact(sorted)
}
