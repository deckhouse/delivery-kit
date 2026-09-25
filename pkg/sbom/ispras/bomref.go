package ispras

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

// NamespaceBOMRefs prefixes every BOM ref declared by bom — the metadata
// component and tools, the components, the services, the formulation, the
// vulnerabilities, the compositions and the annotations, all recursively — with
// prefix and rewrites every reference to them accordingly, mutating bom in
// place. A BOM-Link addresses another document and is left alone. Two
// images may reuse one ref for different entities, so refs stay distinct only
// while they carry the name of their image; services of equal identity are
// collapsed again when the image documents are merged.
func NamespaceBOMRefs(bom *cdx.BOM, prefix string) {
	refMap := map[string]string{}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		namespaceRef(&bom.Metadata.Component.BOMRef, prefix, refMap)
		namespaceComponentBOMRefs(lo.FromPtr(bom.Metadata.Component.Components), prefix, refMap)
	}
	if bom.Metadata != nil && bom.Metadata.Tools != nil {
		namespaceComponentBOMRefs(lo.FromPtr(bom.Metadata.Tools.Components), prefix, refMap)
		namespaceServiceBOMRefs(lo.FromPtr(bom.Metadata.Tools.Services), prefix, refMap)
	}
	namespaceComponentBOMRefs(lo.FromPtr(bom.Components), prefix, refMap)
	namespaceServiceBOMRefs(lo.FromPtr(bom.Services), prefix, refMap)

	for i := range lo.FromPtr(bom.Formulation) {
		formula := &(*bom.Formulation)[i]
		namespaceRef(&formula.BOMRef, prefix, refMap)
		namespaceComponentBOMRefs(lo.FromPtr(formula.Components), prefix, refMap)
		namespaceServiceBOMRefs(lo.FromPtr(formula.Services), prefix, refMap)
	}
	for i := range lo.FromPtr(bom.Vulnerabilities) {
		namespaceRef(&(*bom.Vulnerabilities)[i].BOMRef, prefix, refMap)
	}
	for i := range lo.FromPtr(bom.Compositions) {
		namespaceRef(&(*bom.Compositions)[i].BOMRef, prefix, refMap)
	}
	for i := range lo.FromPtr(bom.Annotations) {
		namespaceRef(&(*bom.Annotations)[i].BOMRef, prefix, refMap)
	}

	namespaceUnknown := func(ref string) {
		if _, known := refMap[ref]; known || ref == "" || strings.HasPrefix(ref, "urn:cdx:") {
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
		namespaceRef(&services[i].BOMRef, prefix, refMap)
		namespaceServiceBOMRefs(lo.FromPtr(services[i].Services), prefix, refMap)
	}
}

func namespaceComponentBOMRefs(components []cdx.Component, prefix string, refMap map[string]string) {
	for i := range components {
		namespaceRef(&components[i].BOMRef, prefix, refMap)
		namespaceComponentBOMRefs(lo.FromPtr(components[i].Components), prefix, refMap)
	}
}

func namespaceRef(ref *string, prefix string, refMap map[string]string) {
	if *ref == "" {
		return
	}

	namespaced := namespacedRef(*ref, prefix)
	refMap[*ref] = namespaced
	*ref = namespaced
}

func namespacedRef(ref, prefix string) string {
	return fmt.Sprintf("%s/%s", prefix, ref)
}
