package attestation

import (
	"fmt"
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

func ResolvePredicateType(shortOrURI string) (string, error) {
	if strings.Contains(shortOrURI, "://") {
		return shortOrURI, nil
	}
	if uri, ok := WellKnownPredicateTypes[shortOrURI]; ok {
		return uri, nil
	}

	known := make([]string, 0, len(WellKnownPredicateTypes))
	for k := range WellKnownPredicateTypes {
		known = append(known, k)
	}
	sort.Strings(known)

	return "", fmt.Errorf("unknown predicate type %q: use a full URI or one of: %s", shortOrURI, strings.Join(known, ", "))
}
