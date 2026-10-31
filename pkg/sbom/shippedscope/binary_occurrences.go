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

// DropBinaryAttributionForVerifiedPaths removes the components a scanner attributed to a
// binary whose composition is already known from the binary itself: verified maps the path
// of such a binary to the content it holds, and a component whose every piece of evidence
// is that binary says nothing the embedded composition does not say better.
//
// Only that case is removed. A component is kept when any of its binary occurrences names
// a path the verification does not cover or content other than what the verified binary
// holds, when a binary could not be classified, when its origin's binary evidence is
// incomplete, and when it carries file evidence of its own: an uncertain claim is still
// evidence, and dropping it would turn uncertainty into a clean document.
//
// Returns how many components were dropped.
func DropBinaryAttributionForVerifiedPaths(_ context.Context, bom *cdx.BOM, verified map[string]string) int {
	if bom == nil || len(verified) == 0 {
		return 0
	}

	dropped := make(map[string]struct{})
	kept := lo.Filter(lo.FromPtr(bom.Components), func(comp cdx.Component, _ int) bool {
		if !attributedToVerifiedBinaries(&comp, verified) {
			return true
		}
		dropped[comp.BOMRef] = struct{}{}

		return false
	})
	if len(dropped) == 0 {
		return 0
	}

	bom.Components = lo.ToPtr(kept)
	if len(kept) == 0 {
		bom.Components = nil
	}
	if bom.Dependencies != nil {
		dependencies := lo.FilterMap(*bom.Dependencies, func(dependency cdx.Dependency, _ int) (cdx.Dependency, bool) {
			if _, gone := dropped[dependency.Ref]; gone {
				return cdx.Dependency{}, false
			}
			if dependency.Dependencies != nil {
				dependency.Dependencies = lo.ToPtr(lo.Filter(*dependency.Dependencies, func(ref string, _ int) bool {
					_, gone := dropped[ref]

					return !gone
				}))
			}

			return dependency, true
		})
		bom.Dependencies = &dependencies
	}

	return len(dropped)
}

func attributedToVerifiedBinaries(comp *cdx.Component, verified map[string]string) bool {
	key, ok := keyOfComponent(comp)
	if !ok || !isBinaryBacked(key.ecosystem) {
		return false
	}
	occurrences, incomplete := binaryOccurrences(comp)
	if incomplete || len(occurrences) == 0 || len(recordedOccurrences(comp)) > 0 {
		return false
	}

	return lo.EveryBy(occurrences, func(occurrence binaryOccurrence) bool {
		return !occurrence.Unknown && verified[occurrence.Path] == occurrence.Digest
	})
}

func HasBinaryBackedComponents(_ context.Context, bom *cdx.BOM) bool {
	found := false
	walkComponents(bom, func(comp *cdx.Component) {
		found = found || BinaryBackedComponent(comp)
	})
	return found
}

// BinaryBackedComponent answers whether this component belongs to an ecosystem that ships
// no files of its own: what the image holds of it is a binary that embeds it, and the
// binary answers for its own composition. A component of any other ecosystem is placed by
// the files of it the image holds.
func BinaryBackedComponent(comp *cdx.Component) bool {
	key, ok := keyOfComponent(comp)

	return ok && isBinaryBacked(key.ecosystem)
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
