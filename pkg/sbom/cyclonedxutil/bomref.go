package cyclonedxutil

import (
	"crypto/sha256"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))

	return fmt.Sprintf("%x", h[:8])
}

func componentIdentity(c cdx.Component) string {
	if c.PackageURL != "" {
		return c.PackageURL
	}

	return fmt.Sprintf("%s:%s/%s@%s", c.Type, c.Group, c.Name, c.Version)
}

func serviceIdentity(s cdx.Service) string {
	return s.Name + ":" + s.Version
}

func remapRef(ref string, refMap map[string]string) string {
	if newRef, ok := refMap[ref]; ok {
		return newRef
	}

	return ref
}

func remapStringSlice(ss *[]string, refMap map[string]string) {
	if ss == nil {
		return
	}

	s := *ss
	for i := range s {
		s[i] = remapRef(s[i], refMap)
	}
}

func remapBOMReferenceSlice(refs *[]cdx.BOMReference, refMap map[string]string) {
	if refs == nil {
		return
	}

	r := *refs
	for i := range r {
		r[i] = cdx.BOMReference(remapRef(string(r[i]), refMap))
	}
}

func resolveRefCollision(ref string, seenRefs map[string]struct{}, hashInput string) string {
	if ref == "" {
		return ""
	}

	if _, exists := seenRefs[ref]; !exists {
		seenRefs[ref] = struct{}{}
		return ""
	}

	newRef := shortHash(hashInput)
	seenRefs[newRef] = struct{}{}

	return newRef
}

func dedupByIdentity[T any](items *[]T, refMap map[string]string, getRef, identity func(T) string) *[]T {
	if items == nil {
		return nil
	}

	seen := map[string]string{}
	var kept []T
	for _, item := range *items {
		ref := getRef(item)
		if ref == "" {
			kept = append(kept, item)
			continue
		}
		id := identity(item)
		if survivor, exists := seen[id]; exists {
			refMap[ref] = survivor
			continue
		}
		seen[id] = ref
		kept = append(kept, item)
	}

	if len(kept) == 0 {
		return nil
	}

	return &kept
}

func resolveCollisions[T any](items *[]T, seenRefs map[string]struct{}, getRef func(T) string, setRef func(*T, string), hashInput func(T, int) string) {
	if items == nil {
		return
	}

	s := *items
	for i := range s {
		ref := getRef(s[i])
		hi := hashInput(s[i], i)
		if newRef := resolveRefCollision(ref, seenRefs, hi); newRef != "" {
			setRef(&s[i], newRef)
		}
	}
}

func resolveComponentCollisions(components *[]cdx.Component, seenRefs map[string]struct{}) {
	if components == nil {
		return
	}

	comps := *components
	for i := range comps {
		ref := comps[i].BOMRef
		if ref == "" {
			continue
		}

		if _, exists := seenRefs[ref]; !exists {
			seenRefs[ref] = struct{}{}
			continue
		}

		var newRef string
		if comps[i].PackageURL != "" {
			newRef = comps[i].PackageURL
		} else {
			newRef = shortHash("component:" + comps[i].Name + ":" + comps[i].Version + ":" + fmt.Sprintf("%d", i))
		}
		comps[i].BOMRef = newRef
		seenRefs[newRef] = struct{}{}
	}
}

func rewriteDependencyRefs(deps *[]cdx.Dependency, refMap map[string]string) {
	if deps == nil {
		return
	}

	d := *deps
	for i := range d {
		d[i].Ref = remapRef(d[i].Ref, refMap)
		remapStringSlice(d[i].Dependencies, refMap)
		remapStringSlice(d[i].Provides, refMap)
	}
}

func rewriteVulnerabilityRefs(vulns *[]cdx.Vulnerability, refMap map[string]string) {
	if vulns == nil {
		return
	}

	v := *vulns
	for i := range v {
		if v[i].Affects == nil {
			continue
		}
		affects := *v[i].Affects
		for j := range affects {
			affects[j].Ref = remapRef(affects[j].Ref, refMap)
		}
		v[i].Affects = &affects
	}
}

func rewriteCompositionRefs(compositions *[]cdx.Composition, refMap map[string]string) {
	if compositions == nil {
		return
	}

	c := *compositions
	for i := range c {
		remapBOMReferenceSlice(c[i].Assemblies, refMap)
		remapBOMReferenceSlice(c[i].Dependencies, refMap)
		remapBOMReferenceSlice(c[i].Vulnerabilities, refMap)
	}
}

func rewriteAnnotationRefs(annotations *[]cdx.Annotation, refMap map[string]string) {
	if annotations == nil {
		return
	}

	a := *annotations
	for i := range a {
		remapBOMReferenceSlice(a[i].Subjects, refMap)
	}
}

func rewriteDeclarationRefs(declarations *cdx.Declarations, refMap map[string]string) {
	if declarations == nil {
		return
	}

	if declarations.Assessors != nil {
		assessors := *declarations.Assessors
		for i := range assessors {
			assessors[i].BOMRef = cdx.BOMReference(remapRef(string(assessors[i].BOMRef), refMap))
		}
		declarations.Assessors = &assessors
	}

	if declarations.Claims != nil {
		claims := *declarations.Claims
		for i := range claims {
			claims[i].BOMRef = remapRef(claims[i].BOMRef, refMap)
		}
		declarations.Claims = &claims
	}

	if declarations.Evidence != nil {
		evidence := *declarations.Evidence
		for i := range evidence {
			evidence[i].BOMRef = remapRef(evidence[i].BOMRef, refMap)
		}
		declarations.Evidence = &evidence
	}
}

func rewriteBOMRefs(bom *cdx.BOM, refMap map[string]string) {
	if len(refMap) == 0 {
		return
	}

	rewriteDependencyRefs(bom.Dependencies, refMap)
	rewriteVulnerabilityRefs(bom.Vulnerabilities, refMap)
	rewriteCompositionRefs(bom.Compositions, refMap)
	rewriteAnnotationRefs(bom.Annotations, refMap)
	rewriteDeclarationRefs(bom.Declarations, refMap)
}

func normalizeBOMRefs(bom *cdx.BOM) {
	if bom == nil {
		return
	}

	refMap := map[string]string{}
	bom.Components = dedupByIdentity(bom.Components, refMap,
		func(c cdx.Component) string { return c.BOMRef },
		componentIdentity,
	)
	bom.Services = dedupByIdentity(bom.Services, refMap,
		func(s cdx.Service) string { return s.BOMRef },
		serviceIdentity,
	)

	seenRefs := map[string]struct{}{}

	resolveComponentCollisions(bom.Components, seenRefs)

	resolveCollisions(bom.Services, seenRefs,
		func(s cdx.Service) string { return s.BOMRef },
		func(s *cdx.Service, ref string) { s.BOMRef = ref },
		func(s cdx.Service, i int) string { return fmt.Sprintf("service:%s:%s:%d", s.Name, s.Version, i) },
	)

	resolveCollisions(bom.Vulnerabilities, seenRefs,
		func(v cdx.Vulnerability) string { return v.BOMRef },
		func(v *cdx.Vulnerability, ref string) { v.BOMRef = ref },
		func(v cdx.Vulnerability, i int) string {
			return fmt.Sprintf("vulnerability:%s:%s:%d", v.ID, v.BOMRef, i)
		},
	)

	resolveCollisions(bom.Compositions, seenRefs,
		func(c cdx.Composition) string { return c.BOMRef },
		func(c *cdx.Composition, ref string) { c.BOMRef = ref },
		func(c cdx.Composition, i int) string { return fmt.Sprintf("composition:%s:%d", c.BOMRef, i) },
	)

	resolveCollisions(bom.Annotations, seenRefs,
		func(a cdx.Annotation) string { return a.BOMRef },
		func(a *cdx.Annotation, ref string) { a.BOMRef = ref },
		func(a cdx.Annotation, i int) string { return fmt.Sprintf("annotation:%s:%d", a.BOMRef, i) },
	)

	if bom.Declarations != nil {
		resolveCollisions(bom.Declarations.Assessors, seenRefs,
			func(a cdx.Assessor) string { return string(a.BOMRef) },
			func(a *cdx.Assessor, ref string) { a.BOMRef = cdx.BOMReference(ref) },
			func(a cdx.Assessor, i int) string { return fmt.Sprintf("assessor:%s:%d", string(a.BOMRef), i) },
		)
		resolveCollisions(bom.Declarations.Claims, seenRefs,
			func(c cdx.Claim) string { return c.BOMRef },
			func(c *cdx.Claim, ref string) { c.BOMRef = ref },
			func(c cdx.Claim, i int) string { return fmt.Sprintf("claim:%s:%d", c.BOMRef, i) },
		)
		resolveCollisions(bom.Declarations.Evidence, seenRefs,
			func(e cdx.DeclarationEvidence) string { return e.BOMRef },
			func(e *cdx.DeclarationEvidence, ref string) { e.BOMRef = ref },
			func(e cdx.DeclarationEvidence, i int) string { return fmt.Sprintf("evidence:%s:%d", e.BOMRef, i) },
		)
	}

	rewriteBOMRefs(bom, refMap)
}
