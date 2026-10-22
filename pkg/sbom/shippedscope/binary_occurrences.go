package shippedscope

import (
	"cmp"
	"context"
	"path"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// PropertyBinaries records completeness of binary evidence: "none" means an origin
// checked its produced binaries and found no match; "unknown" means an origin could
// not establish complete evidence and is preserved when components are merged.
// Positive or digest-bound unknown occurrences replace "none", but do not erase an
// inherited "unknown". With neither a recognized property nor a valid binary occurrence,
// evidence is unknown; absence of this property alone does not prove anything.
const PropertyBinaries = "werf:binaries"

const (
	binaryEvidencePrefix    = "werf:binary:v1:"
	propertyBinariesNone    = "none"
	propertyBinariesUnknown = "unknown"
)

type binaryOccurrence struct {
	Path    string
	Digest  string
	Unknown bool
}

// PrepareBinaryOccurrences records only the fresh scan's local production evidence.
// Inherited origins must be normalized separately before equal components are merged.
func PrepareBinaryOccurrences(ctx context.Context, bom *cdx.BOM, produced *ProducedFiles) {
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok || !isBinaryBacked(key.ecosystem) {
			return
		}
		removeProperty(comp, PropertyBinaries)
		if comp.Evidence != nil {
			kept := lo.Filter(lo.FromPtr(comp.Evidence.Occurrences), func(occ cdx.EvidenceOccurrence, _ int) bool {
				return !strings.HasPrefix(occ.AdditionalContext, "werf:binary:")
			})
			comp.Evidence.Occurrences = &kept
		}
		setProperty(comp, PropertyBinaries, propertyBinariesNone)
	})
	RecordProducedBinaryOccurrences(ctx, bom, produced)
}

// NormalizeInheritedBinaryOccurrences preserves an unknown origin before a merge can
// hide its missing evidence behind another origin's positive or checked-empty record.
func NormalizeInheritedBinaryOccurrences(_ context.Context, bom *cdx.BOM) {
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok || !isBinaryBacked(key.ecosystem) {
			return
		}
		_, incomplete := binaryOccurrences(comp)
		if incomplete {
			addBinaryProperty(comp, propertyBinariesUnknown)
		}
	})
}

// RecordProducedBinaryOccurrences adds local proof without erasing an inherited
// unknown origin. An unreadable binary binds uncertainty to its own content only.
func RecordProducedBinaryOccurrences(_ context.Context, bom *cdx.BOM, produced *ProducedFiles) {
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		if !ok || !isBinaryBacked(key.ecosystem) {
			return
		}
		removeProperty(comp, PropertyShipped)
		if !produced.Known {
			addBinaryProperty(comp, propertyBinariesUnknown)
			return
		}
		for _, file := range produced.Files {
			if file.Classification.TestBinary {
				continue
			}
			verdict := file.Classification.Go
			named := slices.Contains(file.Classification.Modules, key.name)
			if key.ecosystem == EcosystemRust {
				verdict = file.Classification.Rust
				named = slices.Contains(file.Classification.Crates, Crate{Name: key.name, Version: key.version})
			}
			switch verdict {
			case VerdictNone:
				continue
			case VerdictNames:
				if !named {
					continue
				}
			case VerdictUnknown:
			default:
				addBinaryProperty(comp, propertyBinariesUnknown)
				continue
			}
			context := binaryEvidencePrefix + file.Digest
			if verdict == VerdictUnknown {
				context = binaryEvidencePrefix + "unknown:" + file.Digest
			}
			occurrence := cdx.EvidenceOccurrence{Location: file.Path, AdditionalContext: context}
			if _, ok := parseBinaryOccurrence(occurrence); !ok {
				addBinaryProperty(comp, propertyBinariesUnknown)
				continue
			}
			if comp.Evidence == nil {
				comp.Evidence = &cdx.Evidence{}
			}
			occurrences := lo.FromPtr(comp.Evidence.Occurrences)
			if !slices.Contains(occurrences, occurrence) {
				occurrences = append(occurrences, occurrence)
			}
			slices.SortFunc(occurrences, func(a, b cdx.EvidenceOccurrence) int {
				return cmp.Or(cmp.Compare(a.Location, b.Location), cmp.Compare(a.AdditionalContext, b.AdditionalContext))
			})
			comp.Evidence.Occurrences = &occurrences
			properties := lo.Filter(lo.FromPtr(comp.Properties), func(prop cdx.Property, _ int) bool {
				return prop.Name != PropertyBinaries || prop.Value != propertyBinariesNone
			})
			comp.Properties = &properties
		}
	})
}

func HasBinaryBackedComponents(_ context.Context, bom *cdx.BOM) bool {
	found := false
	walkComponents(bom, func(comp *cdx.Component) {
		key, ok := keyOfComponent(comp)
		found = found || (ok && isBinaryBacked(key.ecosystem))
	})
	return found
}

func addBinaryProperty(comp *cdx.Component, value string) {
	property := cdx.Property{Name: PropertyBinaries, Value: value}
	properties := lo.FromPtr(comp.Properties)
	if !slices.Contains(properties, property) {
		comp.Properties = lo.ToPtr(append(properties, property))
	}
}

func parseBinaryOccurrence(occurrence cdx.EvidenceOccurrence) (binaryOccurrence, bool) {
	if !strings.HasPrefix(occurrence.AdditionalContext, binaryEvidencePrefix) || !path.IsAbs(occurrence.Location) || path.Clean(occurrence.Location) != occurrence.Location {
		return binaryOccurrence{}, false
	}
	context := strings.TrimPrefix(occurrence.AdditionalContext, binaryEvidencePrefix)
	unknown := strings.HasPrefix(context, "unknown:")
	context = strings.TrimPrefix(context, "unknown:")
	if !strings.HasPrefix(context, digestPrefix) {
		return binaryOccurrence{}, false
	}
	hex := strings.TrimPrefix(context, digestPrefix)
	if len(hex) != 64 || strings.IndexFunc(hex, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) >= 0 {
		return binaryOccurrence{}, false
	}
	return binaryOccurrence{Path: occurrence.Location, Digest: context, Unknown: unknown}, true
}

func binaryOccurrences(comp *cdx.Component) ([]binaryOccurrence, bool) {
	var occurrences []binaryOccurrence
	complete, incomplete := false, false
	for _, property := range lo.FromPtr(comp.Properties) {
		if property.Name != PropertyBinaries {
			continue
		}
		if property.Value == propertyBinariesNone {
			complete = true
		} else {
			incomplete = true
		}
	}
	if comp.Evidence != nil {
		for _, raw := range lo.FromPtr(comp.Evidence.Occurrences) {
			if !strings.HasPrefix(raw.AdditionalContext, "werf:binary:") {
				continue
			}
			occurrence, ok := parseBinaryOccurrence(raw)
			if !ok {
				incomplete = true
				continue
			}
			occurrences = append(occurrences, occurrence)
			complete = true
		}
	}
	return occurrences, incomplete || !complete
}

func binaryDecision(comp *cdx.Component, indexIncomplete bool, byDigest map[string][]string) Decision {
	occurrences, incomplete := binaryOccurrences(comp)
	unknownPresent := false
	for _, occurrence := range occurrences {
		if len(byDigest[occurrence.Digest]) == 0 {
			continue
		}
		if occurrence.Unknown {
			unknownPresent = true
			continue
		}
		return Decision{Shipped: true, Reason: ReasonBinaryInherited, Matched: byDigest[occurrence.Digest]}
	}
	if unknownPresent {
		return Decision{Shipped: true, Reason: ReasonFailOpen}
	}
	if incomplete || indexIncomplete {
		return Decision{Shipped: true, Reason: ReasonNoData}
	}
	return Decision{Reason: ReasonNotLinked}
}
