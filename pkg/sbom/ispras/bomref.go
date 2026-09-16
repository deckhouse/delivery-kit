package ispras

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

// NamespaceBOMRefs prefixes every BOM ref declared by bom — the metadata
// component and the components recursively — with prefix and rewrites every
// reference to them accordingly, mutating bom in place.
func NamespaceBOMRefs(bom *cdx.BOM, prefix string) {
	refMap := map[string]string{}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		namespaceComponentBOMRef(bom.Metadata.Component, prefix, refMap)
	}
	namespaceComponentBOMRefs(lo.FromPtr(bom.Components), prefix, refMap)

	for _, dep := range lo.FromPtr(bom.Dependencies) {
		if _, known := refMap[dep.Ref]; !known && dep.Ref != "" {
			refMap[dep.Ref] = namespacedRef(dep.Ref, prefix)
		}
		for _, d := range lo.FromPtr(dep.Dependencies) {
			if _, known := refMap[d]; !known && d != "" {
				refMap[d] = namespacedRef(d, prefix)
			}
		}
	}

	cyclonedxutil.RewriteRefs(bom, refMap)
}

func namespaceComponentBOMRefs(components []cdx.Component, prefix string, refMap map[string]string) {
	for i := range components {
		namespaceComponentBOMRef(&components[i], prefix, refMap)
		namespaceComponentBOMRefs(lo.FromPtr(components[i].Components), prefix, refMap)
	}
}

func namespaceComponentBOMRef(comp *cdx.Component, prefix string, refMap map[string]string) {
	if comp.BOMRef == "" {
		return
	}

	namespaced := namespacedRef(comp.BOMRef, prefix)
	refMap[comp.BOMRef] = namespaced
	comp.BOMRef = namespaced
}

func namespacedRef(ref, prefix string) string {
	return fmt.Sprintf("%s/%s", prefix, ref)
}
