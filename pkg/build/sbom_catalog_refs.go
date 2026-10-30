package build

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

// The verified composition names its components by bom-refs of its own
// ("urn:dk:component:sha256:…"), and its catalog points at them: each record names the
// components the file it describes was made of, and the catalog holds those components
// under the same names.
//
// Those names do not survive publication. The verified document is merged into the
// result, and both the merge and the canonicalisation that follows rename bom-refs - the
// merge to keep two documents' refs apart, the canonicalisation when it finds two
// components to be one and folds them together. What a reader is handed would be a
// document whose components answer to derived purl refs, with a catalog still naming the
// refs the verification used: no record could be resolved to a component at all, which is
// the one thing a catalog exists to allow.
//
// So each component is followed from the verification to the published document, and the
// catalog is rewritten to the names it ends up with there. Following is by what a
// component is rather than by what it is called, because a label is exactly the thing
// these passes change. It is done in three steps because there are two kinds of change
// between the merge and publication, and no one moment sees both:
//
//   - when the verified document is merged in, nothing has altered its components yet, so
//     each of them is found in the result by its identity;
//   - the patchers then rewrite some of them - the Go patcher gives a module whose build
//     left it at `(devel)` the version a tag resolves to, changing its version and its
//     purl - so what each followed component now is, is read off the document before the
//     last renaming;
//   - the canonicalisation renames refs and folds components it finds to be one, without
//     altering what any of them is, so each is found again by the identity just read.
//
// A component that goes missing on the way is a hole in what is about to be published: a
// record naming it could be resolved to nothing. It is refused here rather than shipped
// and discovered by whoever reads it.
//
// The verified document itself is never edited. It is the record of what this build
// proved, it is read again for every platform of the image, and nothing here is entitled
// to change it.
type catalogRefs struct {
	// published is, for each ref the verification used, the ref the result gives it.
	published map[string]string
	// identities is what each of those components is, read after the patchers ran.
	identities map[string]string
}

// trackCatalogRefs finds each verified component in the result it was just merged into.
func trackCatalogRefs(result, verified *cdx.BOM) (*catalogRefs, error) {
	published, err := publishedRefsOf(verified, result)
	if err != nil {
		return nil, err
	}

	return &catalogRefs{published: published}, nil
}

// observe reads what the followed components are, after everything that rewrites them has
// run and before the last pass that renames them.
func (c *catalogRefs) observe(result *cdx.BOM) error {
	byRef := map[string]cdx.Component{}
	eachComponent(result, func(comp cdx.Component) {
		if _, taken := byRef[comp.BOMRef]; !taken {
			byRef[comp.BOMRef] = comp
		}
	})

	c.identities = make(map[string]string, len(c.published))
	var lost []string
	for verified, ref := range c.published {
		comp, held := byRef[ref]
		if !held {
			lost = append(lost, ref)

			continue
		}
		c.identities[verified] = cyclonedxutil.ComponentIdentity(comp)
	}
	if len(lost) > 0 {
		sort.Strings(lost)

		return fmt.Errorf("invalid: the document lost components the verification proved: %s", strings.Join(lost, ", "))
	}

	return nil
}

// rewrite names, in the catalog the published document carries, the components that
// document declares.
func (c *catalogRefs) rewrite(published *cdx.BOM) error {
	property, found := catalogPropertyOf(published)
	if !found {
		return nil
	}

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

	translate := func(ref string) (string, error) {
		identity, followed := c.identities[ref]
		if !followed {
			return "", fmt.Errorf("the verification did not prove %s", ref)
		}
		name, declared := byIdentity[identity]
		if !declared {
			return "", fmt.Errorf("the published document holds no component for %s", ref)
		}

		return name, nil
	}

	var catalog nativegate.Catalog
	if err := json.Unmarshal([]byte(property.Value), &catalog); err != nil {
		return fmt.Errorf("read the verified catalog: %w", err)
	}

	// A catalog holds each component under its own ref, and a reader of it checks that
	// the two agree. Renaming the key alone would leave the component inside still
	// answering to the name the verification gave it.
	components := make(map[string]cdx.Component, len(catalog.Components))
	for ref, component := range catalog.Components {
		name, err := translate(ref)
		if err != nil {
			return err
		}
		component.BOMRef = name
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

	// What is about to be published is read back the way a consumer reads it. This is
	// the whole point of the rewriting, and it is cheap enough to confirm rather than
	// assume.
	if _, err := nativegate.ReadCatalog([]*cdx.BOM{published}); err != nil {
		return fmt.Errorf("the rewritten catalog does not load: %w", err)
	}

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
		switch name, known := byIdentity[cyclonedxutil.ComponentIdentity(comp)]; {
		case known:
			refs[comp.BOMRef] = name
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
		if (*bom.Metadata.Properties)[i].Name == nativegate.CatalogProperty {
			return &(*bom.Metadata.Properties)[i], true
		}
	}

	return nil, false
}
