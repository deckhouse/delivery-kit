package shippedscope

import (
	"context"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/logboek"
)

// PropertyShipped is written on a component the image does not ship. Only the negative
// case is recorded: a component without the property is one the image ships, one nothing
// is known about, or one written by a werf that did not look.
//
// The property describes one image, so it is the verdict of the image whose SBOM carries
// it and of no other. A component inherited from a donor arrives carrying the donor's
// verdict, which says where the component was in the donor's image rather than in this
// one, and MarkNotShipped drops it before deciding anew.
const PropertyShipped = "werf:shipped"

const propertyShippedFalse = "false"

const digestPrefix = "sha256:"

// MarkNotShipped decides, for every component of the BOM whose files an ecosystem can
// describe, whether this image ships it, and writes PropertyShipped on the ones it does
// not. Nothing is removed: a component the rule calls absent is still a component the
// image's SBOM declared, and this first increment records the verdict to be looked at on
// real builds before anything acts on it.
//
// Runs after RecordOccurrences, on the occurrences it leaves: for a component this image
// installed those are the files the image holds, and for one inherited from a donor whose
// files this image has no manifest for they are the donor's, which is what lets the rule
// find them by content wherever an import put them.
//
// Go modules and crates are kept untouched. Each is proven by the binaries this image's
// own build produced, and that set is not established here, so the rule is given none and
// fails open on all of them.
//
// Components are passed to the rule together rather than one at a time: whether a file
// proves the component that claims it depends on which other components claim the same
// bytes.
func MarkNotShipped(ctx context.Context, bom *cdx.BOM, filesets *Filesets) int {
	if bom == nil || filesets == nil || filesets.Index == nil {
		return 0
	}

	var components []Component
	var judged []*cdx.Component

	walkComponents(bom, func(comp *cdx.Component) {
		removeProperty(comp, PropertyShipped)

		key, ok := keyOfComponent(comp)
		if !ok {
			return
		}
		// The image carries os-pm packages installed by a pm that wrote no file list, so
		// what the rule would weigh for them is a donor's record of files this image
		// cannot confirm either way.
		if key.ecosystem == EcosystemOSPM && filesets.OSPMFileListMissing {
			return
		}

		components = append(components, Component{
			Ecosystem:   key.ecosystem,
			Name:        key.name,
			Version:     key.version,
			Occurrences: occurrencesOf(comp),
		})
		judged = append(judged, comp)
	})

	if len(components) == 0 {
		return 0
	}

	count := 0
	for i, decision := range Match(ctx, components, ProducedBinaries{}, filesets.Index) {
		if decision.Shipped {
			continue
		}

		setProperty(judged[i], PropertyShipped, propertyShippedFalse)
		count++

		logboek.Context(ctx).Debug().LogF("not shipped %s %s@%s (%s): checked %d files, 0 matches\n",
			components[i].Ecosystem, components[i].Name, components[i].Version, decision.Reason, decision.Checked)
	}

	return count
}

// occurrencesOf reads back what werf recorded of a component's files. An occurrence
// without a digest or the symlink marker came from somewhere else — a scanner noting where
// it saw a package, a document merged in — and says nothing about content; a component
// carrying none of werf's own is one nothing is known about, not one whose files were
// looked for and missed.
func occurrencesOf(comp *cdx.Component) []Occurrence {
	if comp.Evidence == nil || comp.Evidence.Occurrences == nil {
		return nil
	}

	recorded := *comp.Evidence.Occurrences
	occurrences := make([]Occurrence, 0, len(recorded))
	for _, occurrence := range recorded {
		switch {
		case occurrence.AdditionalContext == symlinkContext:
			occurrences = append(occurrences, Occurrence{Path: occurrence.Location, Symlink: true})
		case strings.HasPrefix(occurrence.AdditionalContext, digestPrefix):
			occurrences = append(occurrences, Occurrence{Path: occurrence.Location, Digest: occurrence.AdditionalContext})
		}
	}

	if len(recorded) > 0 && len(occurrences) == 0 {
		return nil
	}

	return occurrences
}

func setProperty(comp *cdx.Component, name, value string) {
	properties := lo.FromPtr(comp.Properties)
	for i := range properties {
		if properties[i].Name == name {
			properties[i].Value = value
			comp.Properties = &properties

			return
		}
	}

	properties = append(properties, cdx.Property{Name: name, Value: value})
	comp.Properties = &properties
}

func removeProperty(comp *cdx.Component, name string) {
	properties := lo.FromPtr(comp.Properties)
	kept := lo.Filter(properties, func(property cdx.Property, _ int) bool {
		return property.Name != name
	})
	if len(kept) == len(properties) {
		return
	}

	comp.Properties = &kept
}
