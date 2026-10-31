package nativegate

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// packageInstallStage is the one boundary of a Deckhouse build where a package manager
// opens and installs packets, and so the only snapshot whose receipt opens them.
const packageInstallStage = "packages"

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
			// An empty file is every empty file. Its bytes single nothing out, and
			// letting them speak would bind every empty file in the image to all of
			// them at once.
			if file.Size == 0 {
				continue
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
		// Bytes carry a binding to where content went, and a path that came through
		// this stage untouched is not where anything went. It stood there before,
		// with nothing bound to it, and the stage that did not write it has said
		// nothing new about it - least of all that it is now one of the files it
		// happens to be byte for byte.
		if previous, stood := before.Files[path]; stood && previous == file {
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

// A stage that installs rather than builds puts files in place whose origin is not a
// question of bytes. A dependency stage holds whatever it imports plus its own base; a
// packages stage holds what a package manager unpacked, and each of those files is
// identified by the package it came out of - the module zip's own hash, checked where the
// package is installed - not by resembling something else in the image.
//
// Files of such a stage are a trap for the byte carry in particular. A Go module cache is
// full of small fixtures and golden files, and a vendored tree of declared sources is full
// of the same ones; `huffman-null-max.dyn.expect` is the same handful of bytes wherever it
// came from. Binding one to the other says the packages stage took a file out of a declared
// source, which it did not do, and binding it to six of them at once says nothing at all
// while sinking the context that needed it.
func installsRatherThanBuilds(stageName string) bool {
	return stageName == packageInstallStage || strings.HasPrefix(stageName, "dependencies")
}

// retainedOriginalMatches keeps the bindings of the paths a stage left exactly as they
// were, and gives none to anything else.
func retainedOriginalMatches(before *shippedscope.FileIndex, matches originalMatches, after *shippedscope.FileIndex) originalMatches {
	kept := make(originalMatches, len(matches))
	for held, bindings := range matches {
		if file, exists := after.Files[held]; exists && file == before.Files[held] {
			kept[held] = slices.Clone(bindings)
		}
	}

	return kept
}
