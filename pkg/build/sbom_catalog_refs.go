package build

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

// The verified composition names its components by bom-refs of its own
// ("urn:dk:component:sha256:…"), and its catalog points at them: each record names the
// components the file it describes was made of, and the catalog holds those components
// under the same names.
//
// Those names do not survive publication. The verified document is merged into the
// result, and both the merge and the canonicalisation that follows rename bom-refs - the
// merge to keep two documents' refs apart, the canonicalisation when it finds two
// components to be one and folds them together. What a reader is handed is a document
// whose components answer to derived purl refs, with a catalog still naming the refs the
// verification used. No record could then be resolved to a component at all, which is the
// one thing the catalog exists to allow.
//
// The refs are therefore translated at the moment the catalog is grafted on, by what a
// component is rather than by what it was called: every pass between the verification and
// publication preserves the identity of a component while renaming its label, so a
// component is looked up in the published document by that identity and the catalog is
// rewritten to the label it has there.
//
// This is done here rather than by keeping the verification's refs unchanged through the
// merge, which would not be enough: when two components are found to be one, the surviving
// ref is the one the earlier of them carried, and a component of the scan standing before
// the verified one takes its place in the document. The catalog would then name a ref no
// component declares, which is the defect it is meant to prevent. Translating at the end
// is also indifferent to how many passes run in between, and to what the patchers do.
// The catalog is rewritten where it now stands, on the published document, and the
// verified one is left exactly as it was: it is the record of what this build proved, it
// is read again for every platform of the image, and nothing here is entitled to edit it.
func rewriteCatalogRefs(published, verified *cdx.BOM) error {
	property, found := catalogPropertyOf(published)
	if !found {
		return nil
	}

	refs, err := publishedRefsOf(verified, published)
	if err != nil {
		return err
	}

	var catalog verifiedCatalog
	if err := json.Unmarshal([]byte(property.Value), &catalog); err != nil {
		return fmt.Errorf("read the verified catalog: %w", err)
	}

	translate := func(ref string) (string, error) {
		published, known := refs[ref]
		if !known {
			return "", fmt.Errorf("the published document holds no component for %s", ref)
		}

		return published, nil
	}

	components := make(map[string]json.RawMessage, len(catalog.Components))
	for ref, component := range catalog.Components {
		name, err := translate(ref)
		if err != nil {
			return err
		}
		components[name] = component
	}
	catalog.Components = components

	for i := range catalog.Records {
		record := &catalog.Records[i]
		for _, list := range []*[]string{&record.Components, &record.Owners} {
			for j, ref := range *list {
				name, err := translate(ref)
				if err != nil {
					return fmt.Errorf("%s: %w", record.Path, err)
				}
				(*list)[j] = name
			}
		}
	}

	rewritten, err := json.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("write the verified catalog: %w", err)
	}
	property.Value = string(rewritten)

	return nil
}

// publishedRefsOf says, for every component the verification declared, which ref the
// published document gives it.
//
// A component the published document does not hold is a hole in what is about to be
// published: a record naming it could be resolved to nothing, and a document that cannot
// say what a file was made of should not say it at all. It is refused here rather than
// shipped and discovered by whoever reads it.
func publishedRefsOf(verified, published *cdx.BOM) (map[string]string, error) {
	byIdentity := map[string]string{}
	eachComponent(published, func(comp cdx.Component) {
		identity := cyclonedxutil.ComponentIdentity(comp)
		if identity == "" || comp.BOMRef == "" {
			return
		}
		if _, taken := byIdentity[identity]; !taken {
			byIdentity[identity] = comp.BOMRef
		}
	})

	refs := map[string]string{}
	var unresolved []string
	eachComponent(verified, func(comp cdx.Component) {
		if comp.BOMRef == "" {
			return
		}
		switch published, known := byIdentity[cyclonedxutil.ComponentIdentity(comp)]; {
		case known:
			refs[comp.BOMRef] = published
		default:
			unresolved = append(unresolved, comp.BOMRef)
		}
	})
	if len(unresolved) > 0 {
		sort.Strings(unresolved)

		return nil, fmt.Errorf("invalid: the published document holds no component the verification proved: %s",
			strings.Join(unresolved, ", "))
	}

	return refs, nil
}

func eachComponent(bom *cdx.BOM, visit func(cdx.Component)) {
	if bom == nil {
		return
	}
	var walk func(components *[]cdx.Component)
	walk = func(components *[]cdx.Component) {
		for _, comp := range lo.FromPtr(components) {
			visit(comp)
			walk(comp.Components)
		}
	}
	walk(bom.Components)
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		walk(bom.Metadata.Component.Components)
	}
}

func catalogPropertyOf(bom *cdx.BOM) (*cdx.Property, bool) {
	if bom == nil || bom.Metadata == nil {
		return nil, false
	}
	for i := range lo.FromPtr(bom.Metadata.Properties) {
		if (*bom.Metadata.Properties)[i].Name == catalogProperty {
			return &(*bom.Metadata.Properties)[i], true
		}
	}

	return nil, false
}

const catalogProperty = "dk:catalog/v4"

// verifiedCatalog is as much of the catalog as this needs to see: the refs, and every
// other field kept as it was written so that rewriting the refs changes nothing else.
type verifiedCatalog struct {
	Schema     string                     `json:"schema"`
	Records    []verifiedCatalogRecord    `json:"records"`
	Components map[string]json.RawMessage `json:"components"`
}

type verifiedCatalogRecord struct {
	Owners      []string        `json:"owners,omitempty"`
	Composition json.RawMessage `json:"composition,omitempty"`
	PMOverlap   string          `json:"pmOverlap,omitempty"`
	Namespace   string          `json:"namespace,omitempty"`
	Path        string          `json:"path"`
	SHA256      string          `json:"sha256"`
	Components  []string        `json:"components"`
	Origin      string          `json:"origin"`
	Profile     string          `json:"profile,omitempty"`
	Tools       json.RawMessage `json:"tools,omitempty"`
}
