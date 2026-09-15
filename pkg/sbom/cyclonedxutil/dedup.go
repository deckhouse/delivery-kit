package cyclonedxutil

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// dedupJSONSlice removes duplicate items from a slice by comparing their JSON
// representations. This matches the "uniqueItems" semantics of JSON Schema
// (deep equality over serialized form). First occurrence wins; order is preserved.
//
// Uses SHA-256 hashing to keep memory usage constant per entry (~32 bytes)
// regardless of item size, which matters for large SBOMs (20k+ components).
func dedupJSONSlice[T any](items []T) []T {
	if len(items) == 0 {
		return items
	}

	seen := make(map[[sha256.Size]byte]struct{}, len(items))
	result := make([]T, 0, len(items))

	for i := range items {
		jsonBytes, err := json.Marshal(items[i])
		if err != nil {
			result = append(result, items[i])
			continue
		}

		hash := sha256.Sum256(jsonBytes)
		if _, exists := seen[hash]; exists {
			continue
		}

		seen[hash] = struct{}{}
		result = append(result, items[i])
	}

	return result
}

// dedupPtrSlice deduplicates the contents of a pointer-to-slice using JSON
// deep equality. Returns nil when the input is nil or the result is empty.
func dedupPtrSlice[T any](items *[]T) *[]T {
	if items == nil {
		return nil
	}

	deduped := dedupJSONSlice(*items)
	if len(deduped) == 0 {
		return nil
	}

	return &deduped
}

// DedupBOM removes duplicate entries from all top-level BOM arrays that have
// "uniqueItems: true" in the CycloneDX 1.6 JSON Schema: components, services,
// dependencies, compositions, vulnerabilities, annotations, and formulation.
func DedupBOM(bom *cdx.BOM) {
	if bom == nil {
		return
	}

	var replacedRefs map[string]string
	bom.Components, replacedRefs = dedupComponentsByPURL(bom.Components)
	bom.Components = dedupPtrSlice(bom.Components)
	bom.ExternalReferences = dedupPtrSlice(bom.ExternalReferences)
	bom.Services = dedupPtrSlice(bom.Services)
	bom.Dependencies = dedupPtrSlice(bom.Dependencies)
	bom.Dependencies = redirectDependencyRefs(bom.Dependencies, replacedRefs)
	bom.Compositions = dedupPtrSlice(bom.Compositions)
	bom.Vulnerabilities = dedupPtrSlice(bom.Vulnerabilities)
	bom.Annotations = dedupPtrSlice(bom.Annotations)
	bom.Formulation = dedupPtrSlice(bom.Formulation)
}

// redirectDependencyRefs points every reference to a deduplicated component at
// the component that survived deduplication, both as a dependency subject and
// as a target. Entries that collapse onto the same subject are merged, and
// references that become self-referential are dropped.
func redirectDependencyRefs(deps *[]cdx.Dependency, replacements map[string]string) *[]cdx.Dependency {
	if deps == nil || len(replacements) == 0 {
		return deps
	}

	result := make([]cdx.Dependency, 0, len(*deps))
	indexByRef := make(map[string]int, len(*deps))

	for _, dep := range *deps {
		ref := dep.Ref
		if survivor, replaced := replacements[ref]; replaced {
			ref = survivor
		}

		idx, merging := indexByRef[ref]
		if !merging {
			idx = len(result)
			indexByRef[ref] = idx
			result = append(result, cdx.Dependency{Ref: ref})
		}

		result[idx].Dependencies = mergeDependencyRefs(ref, result[idx].Dependencies, dep.Dependencies, replacements)
		result[idx].Provides = mergeDependencyRefs(ref, result[idx].Provides, dep.Provides, replacements)
	}

	if len(result) == 0 {
		return nil
	}
	return &result
}

func mergeDependencyRefs(subject string, dst, src *[]string, replacements map[string]string) *[]string {
	if dst == nil && src == nil {
		return nil
	}

	seen := make(map[string]struct{})
	result := make([]string, 0, len(lo.FromPtr(dst))+len(lo.FromPtr(src)))

	for _, refs := range []*[]string{dst, src} {
		for _, ref := range lo.FromPtr(refs) {
			if survivor, replaced := replacements[ref]; replaced {
				ref = survivor
			}

			if ref == subject {
				continue
			}

			if _, exists := seen[ref]; exists {
				continue
			}

			seen[ref] = struct{}{}
			result = append(result, ref)
		}
	}

	if len(result) == 0 {
		return nil
	}
	return &result
}

// dedupComponentsByPURL removes components that share the same normalized purl
// (purl without the package-id query parameter) and deduplicates
// externalReferences inside each kept component. First occurrence wins.
// Components without a purl are always kept.
// Returns the deduplicated slice and a mapping from every removed BOMRef to the
// BOMRef that replaced it.
func dedupComponentsByPURL(components *[]cdx.Component) (*[]cdx.Component, map[string]string) {
	if components == nil {
		return nil, nil
	}

	seen := make(map[string]string)
	replacedRefs := make(map[string]string)
	result := make([]cdx.Component, 0, len(*components))

	for _, comp := range *components {
		comp.ExternalReferences = dedupPtrSlice(comp.ExternalReferences)

		if comp.PackageURL == "" {
			result = append(result, comp)
			continue
		}

		key := normalizePURL(comp.PackageURL)
		if survivor, exists := seen[key]; exists {
			if comp.BOMRef != "" && survivor != "" && comp.BOMRef != survivor {
				replacedRefs[comp.BOMRef] = survivor
			}
			continue
		}

		seen[key] = comp.BOMRef
		result = append(result, comp)
	}

	if len(result) == 0 {
		return nil, replacedRefs
	}

	return &result, replacedRefs
}

// normalizePURL strips the package-id query parameter from a purl for
// deduplication purposes. Syft generates unique package-id values per
// cataloger invocation, making otherwise identical components appear different.
func normalizePURL(purl string) string {
	hashIdx := strings.IndexByte(purl, '#')
	fragment := ""
	base := purl
	if hashIdx >= 0 {
		fragment = purl[hashIdx:]
		base = purl[:hashIdx]
	}

	qIdx := strings.IndexByte(base, '?')
	if qIdx < 0 {
		return purl
	}

	query, err := url.ParseQuery(base[qIdx+1:])
	if err != nil {
		return purl
	}

	query.Del("package-id")

	if len(query) == 0 {
		return base[:qIdx] + fragment
	}

	return base[:qIdx] + "?" + query.Encode() + fragment
}
