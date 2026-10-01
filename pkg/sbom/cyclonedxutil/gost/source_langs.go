package gost

import (
	"context"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

const PropertySourceLangs = "GOST:source_langs"

const sourceLangsSeparator = ","

// SetComponentSourceLangs writes the source languages of a component as a single
// comma-separated GOST:source_langs property. Consumers of the listing read only the
// first property with that name, so the languages must not be spread over repeated ones:
// any repeated GOST:source_langs the component already carries (e.g. inherited from both
// the root component and the document of an imported BOM) is folded into that one.
func SetComponentSourceLangs(_ context.Context, comp *cdx.Component, langs []string) {
	normalized := normalizeSourceLangs(langs)
	if len(normalized) == 0 {
		return
	}

	props := lo.FromPtr(comp.Properties)
	kept := make([]cdx.Property, 0, len(props)+1)
	written := false
	for _, prop := range props {
		if prop.Name != PropertySourceLangs {
			kept = append(kept, prop)
			continue
		}
		if written {
			continue
		}
		kept = append(kept, cdx.Property{Name: PropertySourceLangs, Value: joinSourceLangs(normalized)})
		written = true
	}
	if !written {
		kept = append(kept, cdx.Property{Name: PropertySourceLangs, Value: joinSourceLangs(normalized)})
	}

	comp.Properties = &kept
}

// GetComponentSourceLangs returns the union of the GOST:source_langs values the component
// carries; a canonical component has one, an imported one may still carry repeats.
func GetComponentSourceLangs(_ context.Context, comp *cdx.Component) []string {
	return sourceLangsOfProperties(lo.FromPtr(comp.Properties))
}

func sourceLangsOfProperties(props []cdx.Property) []string {
	var langs []string
	for _, prop := range props {
		if prop.Name == PropertySourceLangs {
			langs = append(langs, splitSourceLangs(prop.Value)...)
		}
	}

	return normalizeSourceLangs(langs)
}

// CollectSourceLangs unions the source languages of the given components and their
// nested ones.
func CollectSourceLangs(ctx context.Context, components []cdx.Component) []string {
	var langs []string
	for i := range components {
		langs = append(langs, GetComponentSourceLangs(ctx, &components[i])...)
		langs = append(langs, CollectSourceLangs(ctx, lo.FromPtr(components[i].Components))...)
	}

	return normalizeSourceLangs(langs)
}

// CollectBOMSourceLangs unions the source languages found anywhere in the image BOM: the
// document properties, the root metadata component with its nested components, and the
// component tree.
func CollectBOMSourceLangs(ctx context.Context, bom *cdx.BOM) []string {
	langs := sourceLangsOfProperties(lo.FromPtr(bom.Properties))
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		langs = append(langs, GetComponentSourceLangs(ctx, bom.Metadata.Component)...)
		langs = append(langs, CollectSourceLangs(ctx, lo.FromPtr(bom.Metadata.Component.Components))...)
	}
	langs = append(langs, CollectSourceLangs(ctx, lo.FromPtr(bom.Components))...)

	return normalizeSourceLangs(langs)
}

// UnionSourceLangs unions language lists into a normalized one (see normalizeSourceLangs);
// it returns nil when no language is left.
func UnionSourceLangs(_ context.Context, lists ...[]string) []string {
	return normalizeSourceLangs(lo.Flatten(lists))
}

// MergeSourceLangsValues unions two raw GOST:source_langs property values into one, so
// that two components folded together by canonicalization keep a single property.
func MergeSourceLangsValues(_ context.Context, a, b string) string {
	return joinSourceLangs(normalizeSourceLangs(append(splitSourceLangs(a), splitSourceLangs(b)...)))
}

// NormalizeSourceLangsValue brings a raw GOST:source_langs value, e.g. one read from an
// imported BOM, to the canonical serialization.
func NormalizeSourceLangsValue(_ context.Context, raw string) string {
	return joinSourceLangs(normalizeSourceLangs(splitSourceLangs(raw)))
}

// normalizeSourceLangs trims, drops empty entries, deduplicates and sorts: every writer,
// canonicalization of imported values included, goes through it, so a given set of
// languages always serializes identically regardless of the order components were
// cataloged or images were assembled in.
func normalizeSourceLangs(langs []string) []string {
	trimmed := lo.FilterMap(langs, func(lang string, _ int) (string, bool) {
		lang = strings.TrimSpace(lang)
		return lang, lang != ""
	})
	if len(trimmed) == 0 {
		return nil
	}

	result := lo.Uniq(trimmed)
	sort.Strings(result)

	return result
}

func joinSourceLangs(langs []string) string {
	return strings.Join(langs, sourceLangsSeparator)
}

func splitSourceLangs(raw string) []string {
	return strings.Split(raw, sourceLangsSeparator)
}
