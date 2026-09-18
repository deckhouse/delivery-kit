package ispras

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

// NamespaceBOMRefs prefixes every BOM ref declared by bom — the metadata
// component and the components recursively — with prefix and rewrites every
// reference to them accordingly, mutating bom in place. Service refs are left
// alone: services are shared between images rather than kept apart, so
// references to them keep their refs too.
func NamespaceBOMRefs(bom *cdx.BOM, prefix string) {
	refMap := map[string]string{}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		namespaceComponentBOMRef(bom.Metadata.Component, prefix, refMap)
	}
	namespaceComponentBOMRefs(lo.FromPtr(bom.Components), prefix, refMap)

	serviceRefs := map[string]struct{}{}
	collectServiceBOMRefs(lo.FromPtr(bom.Services), serviceRefs)

	namespaceUnknown := func(ref string) {
		if _, known := refMap[ref]; known || ref == "" {
			return
		}
		if _, service := serviceRefs[ref]; service {
			return
		}
		refMap[ref] = namespacedRef(ref, prefix)
	}
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		namespaceUnknown(dep.Ref)
		for _, d := range lo.FromPtr(dep.Dependencies) {
			namespaceUnknown(d)
		}
	}

	cyclonedxutil.RewriteRefs(bom, refMap)
}

func collectServiceBOMRefs(services []cdx.Service, refs map[string]struct{}) {
	for _, svc := range services {
		if svc.BOMRef != "" {
			refs[svc.BOMRef] = struct{}{}
		}
		collectServiceBOMRefs(lo.FromPtr(svc.Services), refs)
	}
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
