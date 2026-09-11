package gost

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

const PropertySourceLangs = "GOST:source_langs"

const sourceLangsSeparator = ", "

// SetComponentSourceLangs writes the source languages of a component as a single
// comma-separated GOST:source_langs property. Consumers of the listing read only the
// first property with that name, so the languages must not be spread over repeated ones.
func SetComponentSourceLangs(comp *cdx.Component, langs []string) {
	normalized := normalizeSourceLangs(langs)
	if len(normalized) == 0 {
		return
	}

	newAccessor(comp).setRawProperty(PropertySourceLangs, strings.Join(normalized, sourceLangsSeparator))
}

func GetComponentSourceLangs(comp *cdx.Component) []string {
	raw, found := newAccessor(comp).getRawProperty(PropertySourceLangs)
	if !found {
		return nil
	}

	return normalizeSourceLangs(strings.Split(raw, ","))
}

// CollectSourceLangs unions the source languages of the given components and their
// nested ones, in order of first appearance.
func CollectSourceLangs(components []cdx.Component) []string {
	var langs []string
	for i := range components {
		langs = append(langs, GetComponentSourceLangs(&components[i])...)
		langs = append(langs, CollectSourceLangs(lo.FromPtr(components[i].Components))...)
	}

	return normalizeSourceLangs(langs)
}

func normalizeSourceLangs(langs []string) []string {
	trimmed := lo.FilterMap(langs, func(lang string, _ int) (string, bool) {
		lang = strings.TrimSpace(lang)
		return lang, lang != ""
	})
	if len(trimmed) == 0 {
		return nil
	}

	return lo.Uniq(trimmed)
}
