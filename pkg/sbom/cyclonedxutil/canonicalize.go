package cyclonedxutil

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

// Canonicalize collapses duplicate entities in bom and keeps every BOM ref
// pointing at an entity that still exists. It is the single place that defines
// entity identity: a component is identified by its purl (without the
// package-id qualifier) or, when it has no purl, by type, group, name and
// version; a service by group, name and version; a dependency by its ref; a
// vulnerability by id and source; an external reference by type, url and
// comment; a property by name and value.
//
// Duplicates are merged rather than dropped: the surviving entity takes over
// the external references and properties of its duplicates, and every ref that
// pointed at a duplicate is rewritten to the survivor. Refs that point at
// nothing are removed.
func Canonicalize(bom *cdx.BOM) {
	if bom == nil {
		return
	}

	refMap := map[string]string{}

	bom.Components = canonicalizeComponents(bom.Components, refMap)
	bom.Services = canonicalizeServices(bom.Services, refMap)

	RewriteRefs(bom, refMap)

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		canonicalizeComponent(bom.Metadata.Component)
	}

	bom.ExternalReferences = dedupExternalReferences(bom.ExternalReferences)
	bom.Properties = dedupProperties(bom.Properties)
	bom.Vulnerabilities = canonicalizeVulnerabilities(bom.Vulnerabilities)
	bom.Dependencies = canonicalizeDependencies(bom.Dependencies, collectKnownRefs(bom))
	bom.Compositions = canonicalizeCompositions(bom.Compositions)
	bom.Annotations = canonicalizeAnnotations(bom.Annotations)
	bom.Formulation = dedupPtrSlice(bom.Formulation)
}

func canonicalizeComponents(components *[]cdx.Component, refMap map[string]string) *[]cdx.Component {
	if components == nil {
		return nil
	}

	index := make(map[string]int, len(*components))
	result := make([]cdx.Component, 0, len(*components))

	for i, comp := range *components {
		comp.Components = canonicalizeComponents(comp.Components, refMap)

		key := componentKey(comp, i)
		if pos, exists := index[key]; exists {
			survivor := &result[pos]
			switch {
			case survivor.BOMRef == "":
				survivor.BOMRef = comp.BOMRef
			case comp.BOMRef != "" && comp.BOMRef != survivor.BOMRef:
				refMap[comp.BOMRef] = survivor.BOMRef
			}
			mergeComponentInto(survivor, comp, refMap)
			continue
		}

		canonicalizeComponent(&comp)
		index[key] = len(result)
		result = append(result, comp)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

// mergeComponentInto folds a duplicate into the component that survives it:
// list-valued data is unioned, scalar data the survivor lacks is taken from
// the duplicate, and scalar data both carry stays as the survivor has it.
func mergeComponentInto(survivor *cdx.Component, dup cdx.Component, refMap map[string]string) {
	survivor.ExternalReferences = appendPtrSlice(survivor.ExternalReferences, dup.ExternalReferences)
	survivor.Properties = appendPtrSlice(survivor.Properties, dup.Properties)
	survivor.Hashes = dedupPtrSlice(appendPtrSlice(survivor.Hashes, dup.Hashes))
	survivor.Licenses = mergeLicenses(survivor.Licenses, dup.Licenses)
	if survivor.CPE == "" {
		survivor.CPE = dup.CPE
	}
	if survivor.Description == "" {
		survivor.Description = dup.Description
	}
	if survivor.Scope == "" {
		survivor.Scope = dup.Scope
	}
	if survivor.Supplier == nil {
		survivor.Supplier = dup.Supplier
	}
	if survivor.Evidence == nil {
		survivor.Evidence = dup.Evidence
	}

	if dup.Components != nil {
		merged := append(lo.FromPtr(survivor.Components), *dup.Components...)
		survivor.Components = canonicalizeComponents(&merged, refMap)
	}

	canonicalizeComponent(survivor)
}

// mergeLicenses unions two license lists. CycloneDX forbids mixing SPDX
// expressions with individual licenses in one list, so when either side is an
// expression only the expressions survive.
func mergeLicenses(dest, src *cdx.Licenses) *cdx.Licenses {
	if src == nil {
		return dest
	}

	merged := dedupJSONSlice(append(lo.FromPtr(dest), *src...))
	expressions := lo.Filter(merged, func(l cdx.LicenseChoice, _ int) bool { return l.Expression != "" })
	if len(expressions) > 0 {
		merged = expressions
	}

	return lo.ToPtr(cdx.Licenses(merged))
}

func canonicalizeComponent(comp *cdx.Component) {
	comp.ExternalReferences = dedupExternalReferences(comp.ExternalReferences)
	comp.Properties = dedupProperties(comp.Properties)
}

// componentKey identifies a component by its purl or, without one, by its
// coordinates. A file is the exception: two files with the same name and
// version are the same only if their content is, so files are identified by
// their hashes and a file without hashes is never merged.
func componentKey(comp cdx.Component, index int) string {
	if comp.PackageURL != "" {
		return "purl:" + normalizePURL(comp.PackageURL)
	}

	if comp.Type == cdx.ComponentTypeFile {
		hashes := lo.FromPtr(comp.Hashes)
		if len(hashes) == 0 {
			return fmt.Sprintf("file-unique:%d", index)
		}
		parts := lo.Map(hashes, func(h cdx.Hash, _ int) string { return string(h.Algorithm) + ":" + h.Value })
		sort.Strings(parts)
		return "file:" + comp.Name + "|" + strings.Join(parts, ",")
	}

	return strings.Join([]string{"coords", string(comp.Type), comp.Group, comp.Name, comp.Version}, "|")
}

func canonicalizeServices(services *[]cdx.Service, refMap map[string]string) *[]cdx.Service {
	if services == nil {
		return nil
	}

	index := make(map[string]int, len(*services))
	result := make([]cdx.Service, 0, len(*services))

	for _, svc := range *services {
		svc.Services = canonicalizeServices(svc.Services, refMap)
		svc.ExternalReferences = dedupExternalReferences(svc.ExternalReferences)
		svc.Properties = dedupProperties(svc.Properties)

		key := strings.Join([]string{svc.Group, svc.Name, svc.Version}, "|")
		if pos, exists := index[key]; exists {
			survivor := &result[pos]
			switch {
			case survivor.BOMRef == "":
				survivor.BOMRef = svc.BOMRef
			case svc.BOMRef != "" && svc.BOMRef != survivor.BOMRef:
				refMap[svc.BOMRef] = survivor.BOMRef
			}
			survivor.ExternalReferences = dedupExternalReferences(appendPtrSlice(survivor.ExternalReferences, svc.ExternalReferences))
			survivor.Properties = dedupProperties(appendPtrSlice(survivor.Properties, svc.Properties))
			continue
		}

		index[key] = len(result)
		result = append(result, svc)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

// canonicalizeDependencies merges dependency entries sharing a ref, since a
// dependency graph may describe every entity only once, and drops refs that no
// entity of the BOM declares. A BOM that declares no entity at all carries no
// information about which refs are dangling, so its graph is left alone.
func canonicalizeDependencies(deps *[]cdx.Dependency, knownRefs map[string]struct{}) *[]cdx.Dependency {
	if deps == nil {
		return nil
	}

	if len(knownRefs) == 0 {
		return dedupPtrSlice(deps)
	}

	index := make(map[string]int, len(*deps))
	result := make([]cdx.Dependency, 0, len(*deps))

	for _, dep := range *deps {
		if _, known := knownRefs[dep.Ref]; !known {
			continue
		}

		dep.Dependencies = filterKnownRefs(dep.Dependencies, knownRefs, dep.Ref)
		dep.Provides = filterKnownRefs(dep.Provides, knownRefs, dep.Ref)

		if pos, exists := index[dep.Ref]; exists {
			survivor := &result[pos]
			survivor.Dependencies = dedupStringSlice(appendPtrSlice(survivor.Dependencies, dep.Dependencies))
			survivor.Provides = dedupStringSlice(appendPtrSlice(survivor.Provides, dep.Provides))
			continue
		}

		index[dep.Ref] = len(result)
		result = append(result, dep)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

func canonicalizeVulnerabilities(vulns *[]cdx.Vulnerability) *[]cdx.Vulnerability {
	if vulns == nil {
		return nil
	}

	index := make(map[string]int, len(*vulns))
	result := make([]cdx.Vulnerability, 0, len(*vulns))

	for _, vuln := range *vulns {
		vuln.Affects = dedupPtrSlice(vuln.Affects)
		vuln.Properties = dedupProperties(vuln.Properties)

		key := vuln.ID
		if vuln.Source != nil {
			key += "|" + vuln.Source.Name + "|" + vuln.Source.URL
		}

		if pos, exists := index[key]; exists {
			survivor := &result[pos]
			survivor.Affects = dedupPtrSlice(appendPtrSlice(survivor.Affects, vuln.Affects))
			survivor.Ratings = dedupPtrSlice(appendPtrSlice(survivor.Ratings, vuln.Ratings))
			survivor.Advisories = dedupPtrSlice(appendPtrSlice(survivor.Advisories, vuln.Advisories))
			survivor.CWEs = dedupPtrSlice(appendPtrSlice(survivor.CWEs, vuln.CWEs))
			survivor.References = dedupPtrSlice(appendPtrSlice(survivor.References, vuln.References))
			survivor.Properties = dedupProperties(appendPtrSlice(survivor.Properties, vuln.Properties))
			if survivor.Analysis == nil {
				survivor.Analysis = vuln.Analysis
			}
			continue
		}

		index[key] = len(result)
		result = append(result, vuln)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

func canonicalizeCompositions(compositions *[]cdx.Composition) *[]cdx.Composition {
	if compositions == nil {
		return nil
	}

	result := *compositions
	for i := range result {
		result[i].Assemblies = dedupPtrSlice(result[i].Assemblies)
		result[i].Dependencies = dedupPtrSlice(result[i].Dependencies)
		result[i].Vulnerabilities = dedupPtrSlice(result[i].Vulnerabilities)
	}

	return dedupPtrSlice(&result)
}

func canonicalizeAnnotations(annotations *[]cdx.Annotation) *[]cdx.Annotation {
	if annotations == nil {
		return nil
	}

	result := *annotations
	for i := range result {
		result[i].Subjects = dedupPtrSlice(result[i].Subjects)
	}

	return dedupPtrSlice(&result)
}

func collectKnownRefs(bom *cdx.BOM) map[string]struct{} {
	refs := make(map[string]struct{})

	if bom.Metadata != nil && bom.Metadata.Component != nil && bom.Metadata.Component.BOMRef != "" {
		refs[bom.Metadata.Component.BOMRef] = struct{}{}
	}

	var collectComponents func(components *[]cdx.Component)
	collectComponents = func(components *[]cdx.Component) {
		if components == nil {
			return
		}
		for i := range *components {
			if ref := (*components)[i].BOMRef; ref != "" {
				refs[ref] = struct{}{}
			}
			collectComponents((*components)[i].Components)
		}
	}
	collectComponents(bom.Components)

	var collectServices func(services *[]cdx.Service)
	collectServices = func(services *[]cdx.Service) {
		if services == nil {
			return
		}
		for i := range *services {
			if ref := (*services)[i].BOMRef; ref != "" {
				refs[ref] = struct{}{}
			}
			collectServices((*services)[i].Services)
		}
	}
	collectServices(bom.Services)

	if bom.Metadata != nil && bom.Metadata.Tools != nil {
		collectComponents(bom.Metadata.Tools.Components)
		collectServices(bom.Metadata.Tools.Services)
	}

	for _, formula := range lo.FromPtr(bom.Formulation) {
		collectComponents(formula.Components)
		collectServices(formula.Services)
	}

	return refs
}

// filterKnownRefs keeps the refs of entities the BOM declares, dropping the
// ref of the dependent itself: merging duplicates makes a ref collapse onto the
// entity that depends on it, and an entity does not depend on itself.
func filterKnownRefs(refs *[]string, knownRefs map[string]struct{}, dependentRef string) *[]string {
	if refs == nil {
		return nil
	}

	result := make([]string, 0, len(*refs))
	for _, ref := range *refs {
		if ref == dependentRef {
			continue
		}
		if _, known := knownRefs[ref]; known {
			result = append(result, ref)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return dedupStringSlice(&result)
}

func dedupStringSlice(values *[]string) *[]string {
	if values == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(*values))
	result := make([]string, 0, len(*values))
	for _, value := range *values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

// dedupExternalReferences keeps the first reference of every type-url-comment
// triple and, additionally, only the first vcs reference: the ISPRAS SBOM
// checker reports a component carrying several distinct vcs urls as a defect.
func dedupExternalReferences(refs *[]cdx.ExternalReference) *[]cdx.ExternalReference {
	if refs == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(*refs))
	var vcsSeen bool
	result := make([]cdx.ExternalReference, 0, len(*refs))

	for _, ref := range *refs {
		if ref.Type == cdx.ERTypeVCS {
			if vcsSeen {
				continue
			}
			vcsSeen = true
		}

		key := string(ref.Type) + "|" + ref.URL + "|" + ref.Comment
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, ref)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

// dedupProperties keeps the first property of every name-value pair. GOST
// properties collapse to a single entry per name carrying the strongest value,
// because the ISPRAS SBOM schema allows a component to carry each of them at
// most once and a weaker duplicate must not hide a stronger one.
func dedupProperties(properties *[]cdx.Property) *[]cdx.Property {
	if properties == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(*properties))
	gostPos := make(map[string]int, 2)
	result := make([]cdx.Property, 0, len(*properties))

	for _, prop := range *properties {
		if prop.Name == gost.PropertyAttackSurface || prop.Name == gost.PropertySecurityFunction {
			if pos, exists := gostPos[prop.Name]; exists {
				result[pos].Value = gost.Max(gost.GostValue(result[pos].Value), gost.GostValue(prop.Value)).String()
				continue
			}
			gostPos[prop.Name] = len(result)
			result = append(result, prop)
			continue
		}

		key := prop.Name + "|" + prop.Value
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, prop)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

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
