package sbom

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

func ParseSBOMOutput(output string) (*cdx.BOM, error) {
	jsonBlock, err := extractBOMJSON(output)
	if err != nil {
		return nil, fmt.Errorf("extract BOM JSON: %w", err)
	}

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON([]byte(jsonBlock))
	if err != nil {
		return nil, fmt.Errorf("parse CycloneDX BOM: %w", err)
	}

	return bom, nil
}

func MustParseSBOMOutput(output string) *cdx.BOM {
	bom, err := ParseSBOMOutput(output)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to parse SBOM output:\n%s", output)
	return bom
}

func extractBOMJSON(output string) (string, error) {
	idx := strings.Index(output, `"bomFormat"`)
	if idx == -1 {
		return "", fmt.Errorf(`marker "bomFormat" not found`)
	}

	start := strings.LastIndex(output[:idx], "{")
	if start == -1 {
		return "", fmt.Errorf("no opening { before bomFormat marker")
	}

	end, err := findMatchingBrace(output, start)
	if err != nil {
		return "", err
	}

	return output[start:end], nil
}

// findMatchingBrace returns the index just past the '}' that closes the '{' at s[start].
// It is a minimal brace-matcher used to extract the first top-level JSON object from
// werf CLI output that may contain progress lines, logs, and other noise before/after
// the JSON body. Standard json.Decoder cannot be used directly because the surrounding
// text is not valid JSON. String literals are honored (braces inside "..." are ignored)
// but JSON comments are not — inputs are trusted werf output, not arbitrary user data.
func findMatchingBrace(s string, start int) (int, error) {
	depth := 0
	inString := false
	escape := false

	for i := start; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if inString {
			switch c {
			case '\\':
				escape = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}

	return -1, fmt.Errorf("no matching closing } found from offset %d", start)
}

func FindComponent(bom *cdx.BOM, name, version string) *cdx.Component {
	if bom == nil {
		return nil
	}
	return findComponentIn(bom.Components, func(c *cdx.Component) bool {
		return c.Name == name && c.Version == version
	})
}

func FindComponentByPURL(bom *cdx.BOM, purl string) *cdx.Component {
	if bom == nil {
		return nil
	}
	basePURL := normalizePURL(purl)
	return findComponentIn(bom.Components, func(c *cdx.Component) bool {
		return normalizePURL(c.PackageURL) == basePURL
	})
}

func findComponentIn(comps *[]cdx.Component, match func(*cdx.Component) bool) *cdx.Component {
	if comps == nil {
		return nil
	}
	for i := range *comps {
		c := &(*comps)[i]
		if match(c) {
			return c
		}
		if nested := findComponentIn(c.Components, match); nested != nil {
			return nested
		}
	}
	return nil
}

// normalizePURL returns a canonical form of a PURL for stable comparison:
//   - removes syft's per-run "package-id=<hash>" qualifier (varies across runs);
//   - URL-decodes qualifier values so "%3A" and ":" are treated equal;
//   - sorts remaining qualifiers alphabetically by key.
//
// All other qualifiers (repository_url, arch, etc.) are preserved so identity
// remains asserted.
func normalizePURL(purl string) string {
	q := strings.IndexByte(purl, '?')
	if q < 0 {
		return purl
	}
	base := purl[:q]

	params := map[string]string{}
	for _, kv := range strings.Split(purl[q+1:], "&") {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := kv[:eq]
		if key == "package-id" {
			continue
		}
		val := kv[eq+1:]
		if decoded, err := url.QueryUnescape(val); err == nil {
			val = decoded
		}
		params[key] = val
	}

	if len(params) == 0 {
		return base
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(base)
	for i, k := range keys {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	return b.String()
}

func AssertHasComponent(bom *cdx.BOM, name, version string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"expected component %s@%s not found; got components: %v",
		name, version, componentSummaries(bom))
}

func AssertHasPURL(bom *cdx.BOM, purl string) {
	comp := FindComponentByPURL(bom, purl)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"expected PURL %s not found; got PURLs: %v",
		purl, componentPURLs(bom))
}

func AssertNoComponent(bom *cdx.BOM, name string) {
	walkComponents(bom.Components, func(c *cdx.Component) {
		ExpectWithOffset(1, c.Name).NotTo(Equal(name),
			"unexpected component %s found in BOM", name)
	})
}

// AssertGostPropertyOnMetadata asserts the GOST property on `bom.Metadata.Component`
// only. Use it together with AssertGostPropertyOnComponents when a test needs to
// verify that both surfaces carry the same value (single-image builds, where werf
// applies the resolved image-level GOST config uniformly to metadata and to every
// component — see gost.Upsert in pkg/sbom/cyclonedxutil/gost/upsert.go).
// Splitting the two checks documents the intent explicitly and produces a targeted
// error message when only one of the surfaces regresses.
func AssertGostPropertyOnMetadata(bom *cdx.BOM, propertyName string, expected gost.GostValue) {
	ExpectWithOffset(1, propertyName).To(BeElementOf(gost.PropertyAttackSurface, gost.PropertySecurityFunction),
		"unknown GOST property name %q", propertyName)

	ExpectWithOffset(1, bom.Metadata).NotTo(BeNil(),
		"BOM has no metadata")
	ExpectWithOffset(1, bom.Metadata.Component).NotTo(BeNil(),
		"BOM metadata has no component")

	mc := bom.Metadata.Component
	val, found := findProperty(mc.Properties, propertyName)
	ExpectWithOffset(1, found).To(BeTrue(),
		"metadata.component %q missing GOST property %q", mc.Name, propertyName)
	ExpectWithOffset(1, val).To(Equal(expected.String()),
		"metadata.component %q GOST property %q: expected %q, got %q",
		mc.Name, propertyName, expected.String(), val)
}

// AssertGostPropertyOnComponents asserts the GOST property on every entry of
// `bom.Components` (recursively). Use it on its own for merged BOMs — the merged
// metadata.component is a synthetic product identity built from `--app-name` and
// does not carry GOST from source images.
func AssertGostPropertyOnComponents(bom *cdx.BOM, propertyName string, expected gost.GostValue) {
	ExpectWithOffset(1, propertyName).To(BeElementOf(gost.PropertyAttackSurface, gost.PropertySecurityFunction),
		"unknown GOST property name %q", propertyName)

	checked := 0
	walkComponents(bom.Components, func(c *cdx.Component) {
		val, found := findProperty(c.Properties, propertyName)
		ExpectWithOffset(1, found).To(BeTrue(),
			"component %s@%s missing GOST property %q", c.Name, c.Version, propertyName)
		ExpectWithOffset(1, val).To(Equal(expected.String()),
			"component %s@%s GOST property %q: expected %q, got %q",
			c.Name, c.Version, propertyName, expected.String(), val)
		checked++
	})

	ExpectWithOffset(1, checked).To(BeNumerically(">", 0),
		"BOM has no components to assert GOST property on")
}

func AssertSpecVersion(bom *cdx.BOM, expected cdx.SpecVersion) {
	ExpectWithOffset(1, bom.SpecVersion).To(Equal(expected),
		"expected spec version %q, got %q", expected, bom.SpecVersion)
}

func AssertHasLicense(bom *cdx.BOM, name, version, licenseID string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.Licenses).NotTo(BeNil(),
		"component %s@%s has no licenses", name, version)

	found := false
	var actual []string
	for _, lc := range *comp.Licenses {
		if lc.License == nil {
			continue
		}
		actual = append(actual, lc.License.ID)
		if lc.License.ID == licenseID {
			found = true
			break
		}
	}
	ExpectWithOffset(1, found).To(BeTrue(),
		"component %s@%s: expected license %q, got %v", name, version, licenseID, actual)
}

func AssertHasHash(bom *cdx.BOM, name, version string, algorithm cdx.HashAlgorithm, value string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.Hashes).NotTo(BeNil(),
		"component %s@%s has no hashes", name, version)

	for _, h := range *comp.Hashes {
		if h.Algorithm == algorithm && h.Value == value {
			return
		}
	}
	ExpectWithOffset(1, *comp.Hashes).To(ContainElement(
		cdx.Hash{Algorithm: algorithm, Value: value}),
		"component %s@%s: expected hash %s:%s, got %v", name, version, algorithm, value, *comp.Hashes)
}

func AssertHasExternalReference(bom *cdx.BOM, name, version string, refType cdx.ExternalReferenceType, url string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.ExternalReferences).NotTo(BeNil(),
		"component %s@%s has no external references", name, version)

	for _, ref := range *comp.ExternalReferences {
		if ref.Type == refType && ref.URL == url {
			return
		}
	}
	ExpectWithOffset(1, *comp.ExternalReferences).To(ContainElement(
		cdx.ExternalReference{Type: refType, URL: url}),
		"component %s@%s: expected external ref %s=%s, got %v", name, version, refType, url, *comp.ExternalReferences)
}

func AssertHasProperty(bom *cdx.BOM, name, version, propName, propValue string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)

	val, found := findProperty(comp.Properties, propName)
	ExpectWithOffset(1, found).To(BeTrue(),
		"component %s@%s missing property %q; got: %v",
		name, version, propName, propertyNames(comp.Properties))
	ExpectWithOffset(1, val).To(Equal(propValue),
		"component %s@%s property %q: expected %q, got %q",
		name, version, propName, propValue, val)
}

// AssertHasCPE asserts that a component has the exact primary CPE 2.3 string.
// Use for cases where vendor derivation is deterministic (curated overrides).
func AssertHasCPE(bom *cdx.BOM, name, version, expectedCPE string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.CPE).To(Equal(expectedCPE),
		"component %s@%s primary CPE: expected %q, got %q",
		name, version, expectedCPE, comp.CPE)
}

// AssertHasAnyCPE asserts that a component carries a non-empty primary CPE.
// Use when vendor derivation depends on fixture placeholders and the exact
// value is not predictable, but any inferred CPE should still be present.
func AssertHasAnyCPE(bom *cdx.BOM, name, version string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.CPE).NotTo(BeEmpty(),
		"component %s@%s: expected non-empty primary CPE, got empty", name, version)
}

// AssertHasCPECandidate asserts that a component's evidence.identity contains a
// specific CPE candidate value. Alternative candidates (beyond the primary) are
// stored in Evidence.Identity[].Methods[].Value for downstream NVD matchers.
func AssertHasCPECandidate(bom *cdx.BOM, name, version, expectedCPE string) {
	comp := FindComponent(bom, name, version)
	ExpectWithOffset(1, comp).NotTo(BeNil(),
		"component %s@%s not found", name, version)
	ExpectWithOffset(1, comp.Evidence).NotTo(BeNil(),
		"component %s@%s has no evidence", name, version)
	ExpectWithOffset(1, comp.Evidence.Identity).NotTo(BeNil(),
		"component %s@%s has no evidence.identity", name, version)

	var got []string
	for _, id := range *comp.Evidence.Identity {
		if id.Field != cdx.EvidenceIdentityFieldTypeCPE || id.Methods == nil {
			continue
		}
		for _, m := range *id.Methods {
			got = append(got, m.Value)
			if m.Value == expectedCPE {
				return
			}
		}
	}
	ExpectWithOffset(1, got).To(ContainElement(expectedCPE),
		"component %s@%s: expected CPE candidate %q in evidence.identity, got %v",
		name, version, expectedCPE, got)
}

func AssertDependsOn(bom *cdx.BOM, ref, dependsOnRef string) {
	ExpectWithOffset(1, bom.Dependencies).NotTo(BeNil(),
		"BOM has no dependency graph")

	refBase := normalizePURL(ref)
	targetBase := normalizePURL(dependsOnRef)

	for _, dep := range *bom.Dependencies {
		if normalizePURL(dep.Ref) != refBase {
			continue
		}
		for _, d := range lo.FromPtr(dep.Dependencies) {
			if normalizePURL(d) == targetBase {
				return
			}
		}
		ExpectWithOffset(1, false).To(BeTrue(),
			"ref %q does not depend on %q; deps: %v", refBase, targetBase, lo.FromPtr(dep.Dependencies))
		return
	}
	ExpectWithOffset(1, false).To(BeTrue(),
		"ref %q not found in dependency graph; refs: %v", refBase, dependencyRefs(bom))
}

func findProperty(props *[]cdx.Property, name string) (string, bool) {
	for _, p := range lo.FromPtr(props) {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func componentSummaries(bom *cdx.BOM) []string {
	var out []string
	walkComponents(bom.Components, func(c *cdx.Component) {
		out = append(out, fmt.Sprintf("%s@%s", c.Name, c.Version))
	})
	return out
}

func componentPURLs(bom *cdx.BOM) []string {
	var out []string
	walkComponents(bom.Components, func(c *cdx.Component) {
		if c.PackageURL != "" {
			out = append(out, c.PackageURL)
		}
	})
	return out
}

func walkComponents(comps *[]cdx.Component, fn func(*cdx.Component)) {
	if comps == nil {
		return
	}
	for i := range *comps {
		c := &(*comps)[i]
		fn(c)
		walkComponents(c.Components, fn)
	}
}

func propertyNames(props *[]cdx.Property) []string {
	out := make([]string, 0, len(lo.FromPtr(props)))
	for _, p := range lo.FromPtr(props) {
		out = append(out, p.Name)
	}
	return out
}

func dependencyRefs(bom *cdx.BOM) []string {
	if bom == nil || bom.Dependencies == nil {
		return nil
	}
	out := make([]string, 0, len(*bom.Dependencies))
	for _, d := range *bom.Dependencies {
		out = append(out, d.Ref)
	}
	return out
}
