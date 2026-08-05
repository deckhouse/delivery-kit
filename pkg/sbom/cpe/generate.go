// Portions of this file (candidate generation orchestration and the
// knownVendors preference mechanism) are derived from Anchore syft
// (https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/internal/cpegenerate/generate.go).
//
// Copyright 2020-present Anchore, Inc. and delivery-kit contributors.
// Licensed under the Apache License, Version 2.0.

package cpe

import (
	"sort"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

// Source describes how a CPE was produced.
type Source string

const GeneratedSource Source = "werf-generated"

// vendorSource ranks vendor candidate origins by confidence. Higher value
// means more authoritative; the primary component.cpe is selected from the
// highest-source group so that curated NVD vendors always outrank name-derived
// guesses.
type vendorSource int

const (
	vendorSourceName    vendorSource = iota // derived from the package name and its variations
	vendorSourceRepo                        // pm repo slug owner (Repo="<owner>/<name>")
	vendorSourceURL                         // extracted from OriginalRepo (host prefix or forge regex)
	vendorSourceCurated                     // curated override table (highest confidence)
)

// CPE is a generated Common Platform Enumeration identifier together with its
// provenance. String returns the CPE 2.3 formatted-string binding.
type CPE struct {
	attrs        wfn.Attributes
	source       Source
	vendorSource vendorSource
}

func (c CPE) String() string {
	return c.attrs.BindToFmtString()
}

func (c CPE) Source() Source {
	return c.source
}

type PackageInput struct {
	Name         string
	Version      string
	OriginalRepo string
	Repo         string
}

// vendorCandidate is a vendor value tagged with its origin so downstream
// ordering can prefer authoritative sources over name-derived guesses.
type vendorCandidate struct {
	value  string
	source vendorSource
}

// GenerateForPmPackage returns CPE candidates for a pm package using vendor and
// product heuristics derived from Anchore syft. Returns nil when no valid
// candidate can be produced. The first entry is the primary CPE and reflects
// the highest-confidence vendor source (curated > URL > repo > name).
func GenerateForPmPackage(input PackageInput) []CPE {
	products := productCandidates(input)
	if len(products) == 0 {
		return nil
	}

	vendors := vendorCandidates(input)
	if len(vendors) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	result := make([]CPE, 0, len(products)*len(vendors))
	for _, product := range products {
		for _, vc := range vendors {
			candidate, ok := newGeneratedCPE(product, vc.value, input.Version, vc.source)
			if !ok {
				continue
			}

			key := candidate.String()
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, candidate)
		}
	}

	sort.Sort(bySpecificity(result))
	return result
}

// newGeneratedCPE builds a CPE from the given fields. It reports ok=false when
// the values cannot be bound into a well-formed CPE 2.3 string, in which case
// the candidate is silently skipped (other candidates still cover the package).
func newGeneratedCPE(product, vendor, version string, vendorSrc vendorSource) (CPE, bool) {
	attrs := wfn.Attributes{Part: "a", Vendor: vendor, Product: product, Version: version}

	if _, err := wfn.UnbindFmtString(attrs.BindToFmtString()); err != nil {
		return CPE{}, false
	}

	return CPE{attrs: attrs, source: GeneratedSource, vendorSource: vendorSrc}, true
}

// knownVendors are vendors known to exist in the NVD dictionary; when one is a
// candidate it is returned exclusively to suppress noisier guesses. Ported
// from syft (`apache` is the only entry in the syft upstream list).
var knownVendors = map[string]struct{}{"apache": {}}

func productCandidates(input PackageInput) []string {
	normalized := normalizePackageName(input.Name)

	values := withDelimiterVariations(withDigitVariations([]string{normalized}))
	values = append(values, productFromRepo(input.Repo))
	values = append(values, additionalProductsByPackage[normalized]...)
	if input.Name != normalized {
		values = append(values, additionalProductsByPackage[input.Name]...)
	}

	return uniqueStrings(values...)
}

func vendorCandidates(input PackageInput) []vendorCandidate {
	normalized := normalizePackageName(input.Name)

	var result []vendorCandidate

	// 1. Curated overrides — highest confidence.
	result = appendTaggedVendors(result, additionalVendorsByPackage[normalized], vendorSourceCurated)
	if input.Name != normalized {
		result = appendTaggedVendors(result, additionalVendorsByPackage[input.Name], vendorSourceCurated)
	}

	// 2. URL-derived vendors (host-prefix or forge regex).
	result = appendTaggedVendors(result, candidateVendorsFromURL(input.OriginalRepo), vendorSourceURL)

	// 3. Repo slug owner.
	if v := vendorFromRepo(input.Repo); v != "" {
		result = append(result, vendorCandidate{value: v, source: vendorSourceRepo})
	}

	// 4. Name-derived vendors (delimiter/digit variations plus sub-selections).
	nameProducts := withDelimiterVariations(withDigitVariations([]string{normalized}))
	productOverrides := additionalProductsByPackage[normalized]
	if input.Name != normalized {
		productOverrides = append(productOverrides, additionalProductsByPackage[input.Name]...)
	}
	nameVendors := uniqueStrings(append(append([]string(nil), nameProducts...), productOverrides...)...)
	nameVendors = append(nameVendors, withSubSelections(nameVendors)...)
	result = appendTaggedVendors(result, uniqueStrings(nameVendors...), vendorSourceName)

	result = dedupVendorCandidates(result)

	// knownVendors preference: if a well-known NVD vendor is present, return
	// only it to suppress noisier guesses (e.g. httpd → strictly apache).
	for _, c := range result {
		if _, ok := knownVendors[c.value]; ok {
			return []vendorCandidate{c}
		}
	}

	return result
}

func appendTaggedVendors(dst []vendorCandidate, values []string, src vendorSource) []vendorCandidate {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		dst = append(dst, vendorCandidate{value: v, source: src})
	}
	return dst
}

// dedupVendorCandidates keeps the first occurrence of every vendor value.
// Because iteration order is curated → URL → repo → name, the surviving entry
// always carries the highest-confidence source available for that vendor.
func dedupVendorCandidates(candidates []vendorCandidate) []vendorCandidate {
	seen := make(map[string]struct{}, len(candidates))
	result := make([]vendorCandidate, 0, len(candidates))
	for _, c := range candidates {
		if _, found := seen[c.value]; found {
			continue
		}
		seen[c.value] = struct{}{}
		result = append(result, c)
	}
	return result
}

func productFromRepo(repo string) string {
	_, product, ok := strings.Cut(repo, "/")
	if !ok {
		return ""
	}
	return strings.TrimSpace(product)
}

func vendorFromRepo(repo string) string {
	vendor, _, ok := strings.Cut(repo, "/")
	if !ok {
		return ""
	}
	vendor = strings.TrimSpace(vendor)
	if vendor == "" || vendor == "git" {
		return ""
	}
	return vendor
}

func uniqueStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
