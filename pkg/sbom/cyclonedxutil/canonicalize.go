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

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		bom.Metadata.Component.Components = canonicalizeComponents(bom.Metadata.Component.Components, refMap)
	}
	bom.Components = canonicalizeComponents(bom.Components, refMap)
	bom.Services = canonicalizeServices(bom.Services, refMap)
	bom.Vulnerabilities = canonicalizeVulnerabilities(bom.Vulnerabilities, refMap)

	RewriteRefs(bom, flattenRefMap(dropSurvivingRefs(refMap, collectKnownRefs(bom))))

	CanonicalizeDocument(bom)
}

// dropSurvivingRefs removes from refMap the refs that an entity of the BOM
// still declares. A BOM may reuse one ref for several entities; when a
// duplicate that carried such a ref merges away, the ref still means the
// entity that kept it, so references to it must stay where they are.
func dropSurvivingRefs(refMap map[string]string, knownRefs map[string]struct{}) map[string]string {
	return lo.OmitBy(refMap, func(ref, _ string) bool {
		_, known := knownRefs[ref]
		return known
	})
}

// CanonicalizeDocument does everything Canonicalize does except comparing
// components and services for identity. Use it when the caller has already
// established which entities are the same — merging several SBOMs that must
// keep their components apart, for instance — and only the document-level
// sections still need collapsing and ref checking.
func CanonicalizeDocument(bom *cdx.BOM) {
	if bom == nil {
		return
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		canonicalizeComponent(bom.Metadata.Component)
	}

	bom.ExternalReferences = dedupExternalReferences(bom.ExternalReferences)
	bom.Properties = dedupProperties(bom.Properties)
	for i := range lo.FromPtr(bom.Vulnerabilities) {
		vuln := &(*bom.Vulnerabilities)[i]
		vuln.Affects = dedupPtrSlice(vuln.Affects)
		vuln.Properties = dedupProperties(vuln.Properties)
	}
	knownRefs := collectKnownRefs(bom)
	bom.Dependencies = canonicalizeDependencies(bom.Dependencies, knownRefs)
	if bom.SerialNumber != "" {
		knownRefs[bom.SerialNumber] = struct{}{}
	}
	bom.Compositions = canonicalizeCompositions(bom.Compositions, knownRefs)
	bom.Annotations = canonicalizeAnnotations(bom.Annotations, knownRefs)
	bom.Formulation = dedupPtrSlice(bom.Formulation)
}

// flattenRefMap points every mapping at the entity that finally survives.
// Merging duplicates can map a ref onto another ref that a later merge removes
// in its turn, and only the last one of such a chain still exists. Unlike a
// rename, the intermediate refs are gone, so following the chain is safe; a
// cycle stops at the last ref not seen before.
func flattenRefMap(refMap map[string]string) map[string]string {
	flat := make(map[string]string, len(refMap))

	for ref, target := range refMap {
		seen := map[string]struct{}{ref: {}, target: {}}
		for {
			next, ok := refMap[target]
			if !ok {
				break
			}
			if _, looped := seen[next]; looped {
				break
			}
			seen[next] = struct{}{}
			target = next
		}
		flat[ref] = target
	}

	return flat
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
	survivor.Authors = dedupPtrSlice(appendPtrSlice(survivor.Authors, dup.Authors))
	survivor.OmniborID = dedupStringSlice(appendPtrSlice(survivor.OmniborID, dup.OmniborID))
	survivor.SWHID = dedupStringSlice(appendPtrSlice(survivor.SWHID, dup.SWHID))
	survivor.Tags = dedupStringSlice(appendPtrSlice(survivor.Tags, dup.Tags))
	survivor.Data = dedupPtrSlice(appendPtrSlice(survivor.Data, dup.Data))

	takeString(&survivor.MIMEType, dup.MIMEType)
	takeString(&survivor.Name, dup.Name)
	takeString(&survivor.Version, dup.Version)
	takeString(&survivor.Group, dup.Group)
	takeString(&survivor.Author, dup.Author)
	takeString(&survivor.Publisher, dup.Publisher)
	takeString(&survivor.Description, dup.Description)
	takeString(&survivor.Copyright, dup.Copyright)
	takeString(&survivor.CPE, dup.CPE)
	if survivor.Scope == "" {
		survivor.Scope = dup.Scope
	}
	takePtr(&survivor.Supplier, dup.Supplier)
	takePtr(&survivor.Manufacturer, dup.Manufacturer)
	takePtr(&survivor.SWID, dup.SWID)
	takePtr(&survivor.Modified, dup.Modified)
	takePtr(&survivor.Pedigree, dup.Pedigree)
	takePtr(&survivor.Evidence, dup.Evidence)
	takePtr(&survivor.ReleaseNotes, dup.ReleaseNotes)
	takePtr(&survivor.ModelCard, dup.ModelCard)
	takePtr(&survivor.CryptoProperties, dup.CryptoProperties)
	takePtr(&survivor.Signature, dup.Signature)

	if dup.Components != nil {
		merged := append(lo.FromPtr(survivor.Components), *dup.Components...)
		survivor.Components = canonicalizeComponents(&merged, refMap)
	}

	canonicalizeComponent(survivor)
}

func takeString(dest *string, src string) {
	if *dest == "" {
		*dest = src
	}
}

func takePtr[T any](dest **T, src *T) {
	if *dest == nil {
		*dest = src
	}
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
	comp.ExternalReferences = dedupComponentExternalReferences(comp.ExternalReferences)
	comp.Properties = dedupProperties(comp.Properties)
}

// componentKey identifies a component by its purl or, without one, by its
// coordinates. A file is the exception: two files with the same name are the
// same only if their content is, so files are identified by their name and
// hashes and a file without hashes is never merged.
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

		key := strings.Join([]string{svc.Group, svc.Name, svc.Version}, "|")
		if pos, exists := index[key]; exists {
			survivor := &result[pos]
			switch {
			case survivor.BOMRef == "":
				survivor.BOMRef = svc.BOMRef
			case svc.BOMRef != "" && svc.BOMRef != survivor.BOMRef:
				refMap[svc.BOMRef] = survivor.BOMRef
			}
			mergeServiceInto(survivor, svc, refMap)
			continue
		}

		canonicalizeService(&svc)
		index[key] = len(result)
		result = append(result, svc)
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

// mergeServiceInto folds a duplicate into the service that survives it, the
// same way mergeComponentInto does for components.
func mergeServiceInto(survivor *cdx.Service, dup cdx.Service, refMap map[string]string) {
	survivor.ExternalReferences = appendPtrSlice(survivor.ExternalReferences, dup.ExternalReferences)
	survivor.Properties = appendPtrSlice(survivor.Properties, dup.Properties)
	survivor.Endpoints = dedupStringSlice(appendPtrSlice(survivor.Endpoints, dup.Endpoints))
	survivor.Tags = dedupStringSlice(appendPtrSlice(survivor.Tags, dup.Tags))
	survivor.Data = dedupPtrSlice(appendPtrSlice(survivor.Data, dup.Data))
	survivor.Licenses = mergeLicenses(survivor.Licenses, dup.Licenses)
	takeString(&survivor.Description, dup.Description)
	takeString(&survivor.TrustZone, dup.TrustZone)
	takePtr(&survivor.Provider, dup.Provider)
	takePtr(&survivor.Authenticated, dup.Authenticated)
	takePtr(&survivor.CrossesTrustBoundary, dup.CrossesTrustBoundary)
	takePtr(&survivor.ReleaseNotes, dup.ReleaseNotes)
	takePtr(&survivor.Signature, dup.Signature)

	if dup.Services != nil {
		merged := append(lo.FromPtr(survivor.Services), *dup.Services...)
		survivor.Services = canonicalizeServices(&merged, refMap)
	}

	canonicalizeService(survivor)
}

func canonicalizeService(svc *cdx.Service) {
	svc.ExternalReferences = dedupExternalReferences(svc.ExternalReferences)
	svc.Properties = dedupProperties(svc.Properties)
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

func canonicalizeVulnerabilities(vulns *[]cdx.Vulnerability, refMap map[string]string) *[]cdx.Vulnerability {
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
			switch {
			case survivor.BOMRef == "":
				survivor.BOMRef = vuln.BOMRef
			case vuln.BOMRef != "" && vuln.BOMRef != survivor.BOMRef:
				refMap[vuln.BOMRef] = survivor.BOMRef
			}
			mergeVulnerabilityInto(survivor, vuln)
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

func mergeVulnerabilityInto(survivor *cdx.Vulnerability, dup cdx.Vulnerability) {
	takeString(&survivor.Description, dup.Description)
	takeString(&survivor.Detail, dup.Detail)
	takeString(&survivor.Recommendation, dup.Recommendation)
	takeString(&survivor.Workaround, dup.Workaround)
	takeString(&survivor.Created, dup.Created)
	takeString(&survivor.Published, dup.Published)
	takeString(&survivor.Updated, dup.Updated)
	takeString(&survivor.Rejected, dup.Rejected)
	takePtr(&survivor.Source, dup.Source)
	takePtr(&survivor.ProofOfConcept, dup.ProofOfConcept)
	takePtr(&survivor.Credits, dup.Credits)
	takePtr(&survivor.Tools, dup.Tools)
	takePtr(&survivor.Analysis, dup.Analysis)

	survivor.Affects = dedupPtrSlice(appendPtrSlice(survivor.Affects, dup.Affects))
	survivor.Ratings = dedupPtrSlice(appendPtrSlice(survivor.Ratings, dup.Ratings))
	survivor.Advisories = dedupPtrSlice(appendPtrSlice(survivor.Advisories, dup.Advisories))
	survivor.CWEs = dedupPtrSlice(appendPtrSlice(survivor.CWEs, dup.CWEs))
	survivor.References = dedupPtrSlice(appendPtrSlice(survivor.References, dup.References))
	survivor.Properties = dedupProperties(appendPtrSlice(survivor.Properties, dup.Properties))
}

// canonicalizeCompositions keeps the refs of entities the BOM declares and
// drops a composition left without any. A BOM-Link stays: it addresses an
// entity of another document, which cannot be checked here.
func canonicalizeCompositions(compositions *[]cdx.Composition, knownRefs map[string]struct{}) *[]cdx.Composition {
	if compositions == nil {
		return nil
	}

	result := make([]cdx.Composition, 0, len(*compositions))
	for _, composition := range *compositions {
		composition.Assemblies = filterKnownBOMReferences(composition.Assemblies, knownRefs)
		composition.Dependencies = filterKnownBOMReferences(composition.Dependencies, knownRefs)
		composition.Vulnerabilities = filterKnownBOMReferences(composition.Vulnerabilities, knownRefs)
		if composition.Assemblies == nil && composition.Dependencies == nil && composition.Vulnerabilities == nil {
			continue
		}
		result = append(result, composition)
	}

	return dedupPtrSlice(&result)
}

// canonicalizeAnnotations keeps the subjects the BOM declares and drops an
// annotation left without any. The serial number of the BOM is a subject too:
// an annotation may be about the document itself. A BOM-Link stays: it
// addresses an entity of another document, which cannot be checked here.
func canonicalizeAnnotations(annotations *[]cdx.Annotation, knownRefs map[string]struct{}) *[]cdx.Annotation {
	if annotations == nil {
		return nil
	}

	result := make([]cdx.Annotation, 0, len(*annotations))
	for _, annotation := range *annotations {
		annotation.Subjects = filterKnownBOMReferences(annotation.Subjects, knownRefs)
		if annotation.Subjects == nil {
			continue
		}
		result = append(result, annotation)
	}

	return dedupPtrSlice(&result)
}

func filterKnownBOMReferences(refs *[]cdx.BOMReference, knownRefs map[string]struct{}) *[]cdx.BOMReference {
	if refs == nil {
		return nil
	}

	result := make([]cdx.BOMReference, 0, len(*refs))
	for _, ref := range *refs {
		_, known := knownRefs[string(ref)]
		if known || strings.HasPrefix(string(ref), "urn:cdx:") {
			result = append(result, ref)
		}
	}

	return dedupPtrSlice(&result)
}

func collectKnownRefs(bom *cdx.BOM) map[string]struct{} {
	refs := make(map[string]struct{})

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
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		collectComponents(&[]cdx.Component{*bom.Metadata.Component})
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

	for _, vuln := range lo.FromPtr(bom.Vulnerabilities) {
		if vuln.BOMRef != "" {
			refs[vuln.BOMRef] = struct{}{}
		}
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

// ExternalReferenceCommentResolved marks an external reference whose url was
// looked up from the package purl rather than reported by the package source
// itself. When a component ends up with several vcs links, the ones without
// this mark are preferred: the package manager knows where its package came
// from, a resolver only guesses.
const ExternalReferenceCommentResolved = "resolved from purl"

// dedupComponentExternalReferences keeps the first reference of every
// type-url-comment triple and only one vcs reference: the ISPRAS SBOM checker
// reports a component carrying several distinct vcs urls as a defect. Among
// vcs references the first one not resolved from the purl wins. The document
// and a service may list the sources of many components, so the single-vcs
// rule applies to components only.
func dedupComponentExternalReferences(refs *[]cdx.ExternalReference) *[]cdx.ExternalReference {
	if refs == nil {
		return nil
	}

	vcs, found := lo.Find(*refs, func(ref cdx.ExternalReference) bool {
		return ref.Type == cdx.ERTypeVCS && ref.Comment != ExternalReferenceCommentResolved
	})
	if !found {
		vcs, _ = lo.Find(*refs, func(ref cdx.ExternalReference) bool { return ref.Type == cdx.ERTypeVCS })
	}

	kept := lo.Filter(*refs, func(ref cdx.ExternalReference, _ int) bool {
		return ref.Type != cdx.ERTypeVCS || (ref.URL == vcs.URL && ref.Comment == vcs.Comment)
	})

	return dedupExternalReferences(&kept)
}

// dedupExternalReferences keeps the first reference of every type-url-comment
// triple.
func dedupExternalReferences(refs *[]cdx.ExternalReference) *[]cdx.ExternalReference {
	if refs == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(*refs))
	result := make([]cdx.ExternalReference, 0, len(*refs))

	for _, ref := range *refs {
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
