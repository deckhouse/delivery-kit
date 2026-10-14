package attestation

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// WellKnownPredicateTypes maps cosign-compatible short names to predicate URIs.
// Entries of a PredicateKind are expressed through the kind, which owns the URIs.
var WellKnownPredicateTypes = map[string]string{
	// Resolves to the versioned URI for backward compatibility; alias matching
	// covers the unversioned URI signed artifacts carry.
	PredicateKindOpenVEX.Name:   PredicateKindOpenVEX.UnsignedType,
	PredicateKindCycloneDX.Name: PredicateKindCycloneDX.SignedType,

	"slsaprovenance":  "https://slsa.dev/provenance/v0.2",
	"slsaprovenance1": "https://slsa.dev/provenance/v1",
	"spdxjson":        "https://spdx.dev/Document",
}

// PredicateKind describes an attestation kind whose artifacts may carry different
// predicate URIs depending on how they were published: signed artifacts use the
// unversioned URI (cosign convention), legacy unsigned ones the versioned URI.
// The kind is the unit of artifact identity: slot selection, supersede scoping
// and read-path matching all operate on the full URI set of one kind.
type PredicateKind struct {
	// Name is the cosign-compatible well-known short name.
	Name string

	// SignedType is the predicate URI of signed artifacts.
	SignedType string

	// UnsignedType is the predicate URI of legacy/unsigned artifacts.
	UnsignedType string

	// ImageLevel marks kinds attached to the image (index) digest itself rather
	// than to per-platform manifests.
	ImageLevel bool

	// AliasMatching lets a request for any URI of the kind match every other on
	// read and verify. Kinds without it keep exact predicate matching and use the
	// URI set for slot selection only.
	AliasMatching bool
}

// Types returns every predicate URI the kind is known under.
func (k PredicateKind) Types() []string {
	return []string{k.SignedType, k.UnsignedType}
}

var (
	PredicateKindOpenVEX = PredicateKind{
		Name:          "openvex",
		SignedType:    "https://openvex.dev/ns",
		UnsignedType:  "https://openvex.dev/ns/v0.2.0",
		ImageLevel:    true,
		AliasMatching: true,
	}

	PredicateKindCycloneDX = PredicateKind{
		Name:         "cyclonedx",
		SignedType:   "https://cyclonedx.org/bom",
		UnsignedType: "https://cyclonedx.org/bom/v1.6",
	}
)

var predicateKinds = []PredicateKind{PredicateKindOpenVEX, PredicateKindCycloneDX}

func predicateKindOf(uri string) (PredicateKind, bool) {
	for _, kind := range predicateKinds {
		if slices.Contains(kind.Types(), uri) {
			return kind, true
		}
	}
	return PredicateKind{}, false
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

// PredicateLookupTypes resolves a short name or URI to the predicate URIs a read
// of that kind may land on. It mirrors PredicateTypeMatches: an alias-matching
// kind accepts every URI of the kind, so a read may match any of them; every
// other kind accepts only the resolved URI, so a read must look for that one
// alone — matching a neighboring URI of the same kind would only find an
// artifact the exact check then rejects. Unknown kinds resolve to themselves.
func PredicateLookupTypes(shortOrURI string) ([]string, error) {
	resolved, err := ResolvePredicateType(shortOrURI)
	if err != nil {
		return nil, err
	}
	if kind, ok := predicateKindOf(resolved); ok && kind.AliasMatching {
		return kind.Types(), nil
	}
	return []string{resolved}, nil
}

// PredicateTypeMatches reports whether a found statement predicate satisfies the
// requested one: exactly, or across the URI set of an alias-matching kind.
func PredicateTypeMatches(requested, found string) bool {
	if requested == found {
		return true
	}
	kind, ok := predicateKindOf(requested)
	return ok && kind.AliasMatching && slices.Contains(kind.Types(), found)
}

// ImageLevelPredicateType reports whether attestations of the given predicate
// type are attached to the image (index) digest itself rather than to
// per-platform manifests.
func ImageLevelPredicateType(shortOrURI string) bool {
	resolved, err := ResolvePredicateType(shortOrURI)
	if err != nil {
		return false
	}
	kind, ok := predicateKindOf(resolved)
	return ok && kind.ImageLevel
}
