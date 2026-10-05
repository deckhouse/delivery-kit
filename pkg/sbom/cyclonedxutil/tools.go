package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

const werfToolName = "werf"

// MarkWerfTool records werf among the tools that produced bom, next to the
// scanner that cataloged it. The edges sourced at the root of a werf-produced
// BOM carry a meaning other producers do not share — the packages the image
// declares — so a merge adopts them only from BOMs that carry this mark.
func MarkWerfTool(bom *cdx.BOM, version string) {
	if bom == nil {
		return
	}
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = &cdx.ToolsChoice{}
	}
	if HasWerfTool(bom) {
		return
	}

	bom.Metadata.Tools.Components = lo.ToPtr(append(lo.FromPtr(bom.Metadata.Tools.Components), cdx.Component{
		Type:    cdx.ComponentTypeApplication,
		Name:    werfToolName,
		Version: version,
	}))
}

// HasWerfTool reports whether werf is recorded among the tools that produced bom.
func HasWerfTool(bom *cdx.BOM) bool {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Tools == nil {
		return false
	}
	return lo.ContainsBy(lo.FromPtr(bom.Metadata.Tools.Components), func(comp cdx.Component) bool {
		return comp.Name == werfToolName
	})
}
