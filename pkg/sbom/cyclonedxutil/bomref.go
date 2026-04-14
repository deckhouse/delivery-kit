package cyclonedxutil

import (
	"crypto/sha256"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

func packageID(serial string, index int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", serial, index)))
	return fmt.Sprintf("%x", h[:8])
}

func deriveBomRef(purl, serial string, index int) string {
	id := packageID(serial, index)

	if parsed, err := packageurl.FromString(purl); err == nil {
		parsed.Qualifiers = append(parsed.Qualifiers, packageurl.Qualifier{
			Key:   "package-id",
			Value: id,
		})
		return parsed.ToString()
	}

	return id
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

func rewriteAllRefs(bom *cdx.BOM, refMap map[string]string) {
	if len(refMap) == 0 {
		return
	}

	rewriteDependencyRefs(bom.Dependencies, refMap)
	rewriteVulnerabilityRefs(bom.Vulnerabilities, refMap)
	rewriteCompositionRefs(bom.Compositions, refMap)
	rewriteAnnotationRefs(bom.Annotations, refMap)
	rewriteDeclarationRefs(bom.Declarations, refMap)
}

func ensureUniqueBOMRefs(bom *cdx.BOM) {
	if bom == nil {
		return
	}

	refMap := map[string]string{}
	serial := bom.SerialNumber
	index := 0

	if bom.Components != nil {
		comps := *bom.Components
		for i := range comps {
			oldRef := comps[i].BOMRef
			if oldRef == "" {
				index++
				continue
			}

			newRef := deriveBomRef(comps[i].PackageURL, serial, index)
			if oldRef != newRef {
				refMap[oldRef] = newRef
			}
			comps[i].BOMRef = newRef
			index++
		}
	}

	if bom.Services != nil {
		svcs := *bom.Services
		for i := range svcs {
			oldRef := svcs[i].BOMRef
			if oldRef == "" {
				index++
				continue
			}

			newRef := deriveBomRef("", serial, index)
			if oldRef != newRef {
				refMap[oldRef] = newRef
			}
			svcs[i].BOMRef = newRef
			index++
		}
	}

	rewriteAllRefs(bom, refMap)
}
