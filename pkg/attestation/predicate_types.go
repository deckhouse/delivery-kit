package attestation

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

var WellKnownPredicateTypes = map[string]string{
	"openvex":         "https://openvex.dev/ns/v0.2.0",
	"slsaprovenance":  "https://slsa.dev/provenance/v0.2",
	"slsaprovenance1": "https://slsa.dev/provenance/v1",
	"spdxjson":        "https://spdx.dev/Document",
	"cyclonedx":       "https://cyclonedx.org/bom",
}

func PredicateTypeHelp() string {
	known := make([]string, 0, len(WellKnownPredicateTypes))
	for k := range WellKnownPredicateTypes {
		known = append(known, k)
	}
	sort.Strings(known)
	return strings.Join(known, ", ")
}

func ResolvePredicateType(shortOrURI string) (string, error) {
	if strings.Contains(shortOrURI, "://") {
		return shortOrURI, nil
	}
	if uri, ok := WellKnownPredicateTypes[shortOrURI]; ok {
		return uri, nil
	}

	return "", fmt.Errorf("unknown predicate type %q: use a full URI or one of: %s", shortOrURI, PredicateTypeHelp())
}

// predicateKindAliases groups predicate URIs denoting the same attestation kind:
// signed and legacy artifacts of one kind carry different URIs (unversioned by the
// cosign convention vs versioned legacy), so artifact slot selection must accept
// the whole set. Keyed by every member of the set.
var predicateKindAliases = map[string][]string{
	"https://openvex.dev/ns":         {"https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0"},
	"https://openvex.dev/ns/v0.2.0":  {"https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0"},
	"https://cyclonedx.org/bom":      {"https://cyclonedx.org/bom", "https://cyclonedx.org/bom/v1.6"},
	"https://cyclonedx.org/bom/v1.6": {"https://cyclonedx.org/bom", "https://cyclonedx.org/bom/v1.6"},
}

// PredicateKindAliases resolves a short name or URI to every predicate URI of the
// same attestation kind. Unknown kinds resolve to themselves.
func PredicateKindAliases(shortOrURI string) ([]string, error) {
	resolved, err := ResolvePredicateType(shortOrURI)
	if err != nil {
		return nil, err
	}
	if aliases, ok := predicateKindAliases[resolved]; ok {
		return aliases, nil
	}
	return []string{resolved}, nil
}

// PredicateTypeMatches reports whether a found statement predicate satisfies the
// requested one. OpenVEX predicates match across the versioned/unversioned alias
// set (signed artifacts carry the unversioned URI, legacy ones the versioned);
// every other predicate type requires an exact match.
func PredicateTypeMatches(requested, found string) bool {
	if requested == found {
		return true
	}
	aliases, ok := predicateKindAliases[requested]
	if !ok || !strings.HasPrefix(requested, "https://openvex.dev/") {
		return false
	}
	return slices.Contains(aliases, found)
}

// ImageLevelPredicateType reports whether attestations of the given predicate
// type are attached to the image (index) digest itself rather than to per-platform
// manifests. OpenVEX documents are image-level: one document per image, matching
// vexctl/docker scout behavior.
func ImageLevelPredicateType(shortOrURI string) bool {
	resolved, err := ResolvePredicateType(shortOrURI)
	if err != nil {
		return false
	}
	return slices.Contains(predicateKindAliases["https://openvex.dev/ns"], resolved)
}
