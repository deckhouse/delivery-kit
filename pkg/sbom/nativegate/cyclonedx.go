package nativegate

import (
	"slices"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func (c *Catalog) writeBOM(present map[string]Record, runtimeEdges map[string][]string, target *cdx.BOM) error {
	components := map[string]cdx.Component{}
	deps := []cdx.Dependency{}
	// Where each component stands is recorded as it is written. An image importing a
	// part of this one reads this document and keeps of it what occurs at a path the
	// copy carries; a component stating no whereabouts could not be placed, and this is
	// the only moment at which what was proven knows them.
	owned := map[string][]cdx.EvidenceOccurrence{}
	for name, r := range present {
		ref := r.SHA256 + ":" + name
		hashes := []cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: strings.TrimPrefix(r.SHA256, "sha256:")}}
		components[ref] = cdx.Component{
			Type: cdx.ComponentTypeFile, BOMRef: ref, Name: name, Hashes: &hashes,
			Properties: &[]cdx.Property{{Name: "dk:origin", Value: r.Origin}},
			Evidence:   &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: name, AdditionalContext: r.SHA256}}},
		}
		refs := slices.Clone(r.Components)
		for _, dependency := range runtimeEdges[name] {
			refs = appendUnique(refs, present[dependency].SHA256+":"+dependency)
		}
		sort.Strings(refs)
		deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: &refs})
		for _, ref := range r.Components {
			components[ref] = c.Components[ref]
			owned[ref] = append(owned[ref], cdx.EvidenceOccurrence{Location: name, AdditionalContext: r.SHA256})
		}
	}
	for ref, occurrences := range owned {
		component := components[ref]
		slices.SortFunc(occurrences, func(a, b cdx.EvidenceOccurrence) int { return strings.Compare(a.Location, b.Location) })
		// Whatever else the component's evidence carries is the donor's and stays;
		// only where it stands in this image is this build's to state.
		evidence := cdx.Evidence{}
		if component.Evidence != nil {
			evidence = *component.Evidence
		}
		evidence.Occurrences = &occurrences
		component.Evidence = &evidence
		components[ref] = component
	}
	list := []cdx.Component{}
	for _, comp := range components {
		list = append(list, comp)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].BOMRef < list[j].BOMRef })
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	target.Components = &list
	target.Dependencies = &deps
	if target.Metadata != nil && target.Metadata.Component != nil {
		refs := []string{}
		for name, r := range present {
			refs = append(refs, r.SHA256+":"+name)
		}
		sort.Strings(refs)
		*target.Dependencies = append(*target.Dependencies, cdx.Dependency{Ref: target.Metadata.Component.BOMRef, Dependencies: &refs})
	}
	return nil
}
