package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// DropSyftSourceFileComponents removes the PURL-less type=file components that a syft
// directory-source scan emits for the scanned manifest files themselves (e.g. a
// "/scan/go.mod" file entry). These are not packages, and dedupComponentsByPURL keeps
// PURL-less components, so nothing downstream would drop them. A targeted directory scan
// runs this after each scan so only real package components remain — the property that
// lets the post-scan source-path filter be omitted. Components with a PackageURL, and
// non-file components, are always kept.
func DropSyftSourceFileComponents(bom *cdx.BOM) {
	if bom == nil || bom.Components == nil {
		return
	}

	kept := make([]cdx.Component, 0, len(*bom.Components))
	for _, comp := range *bom.Components {
		if comp.Type == cdx.ComponentTypeFile && comp.PackageURL == "" {
			continue
		}
		kept = append(kept, comp)
	}

	if len(kept) == 0 {
		bom.Components = nil
		return
	}
	*bom.Components = kept
}
