package ispras

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

// NamespaceBOMRefs prefixes every BOM ref declared by bom — the metadata
// component, the components and the services, all recursively — with prefix
// and rewrites every reference to them accordingly, mutating bom in place. Two
// images may reuse one ref for different entities, so refs stay distinct only
// while they carry the name of their image; services of equal identity are
// collapsed again when the image documents are merged.
func NamespaceBOMRefs(bom *cdx.BOM, prefix string) {
	refMap := map[string]string{}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		namespaceComponentBOMRef(bom.Metadata.Component, prefix, refMap)
	}
	namespaceComponentBOMRefs(lo.FromPtr(bom.Components), prefix, refMap)
	namespaceServiceBOMRefs(lo.FromPtr(bom.Services), prefix, refMap)

	namespaceUnknown := func(ref string) {
		if _, known := refMap[ref]; known || ref == "" {
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

func namespaceServiceBOMRefs(services []cdx.Service, prefix string, refMap map[string]string) {
	for i := range services {
		svc := &services[i]
		if svc.BOMRef != "" {
			namespaced := namespacedRef(svc.BOMRef, prefix)
			refMap[svc.BOMRef] = namespaced
			svc.BOMRef = namespaced
		}
		namespaceServiceBOMRefs(lo.FromPtr(svc.Services), prefix, refMap)
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
