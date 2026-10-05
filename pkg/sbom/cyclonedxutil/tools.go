package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

const werfToolName = "werf"

// MarkWerfTool records werf among the tools that produced bom, next to the
// scanner that cataloged it. The edges sourced at the root of a werf-produced
// BOM carry a meaning other producers do not share — the packages the image
// declares — so a merge adopts them only from BOMs that carry this mark. Tools
// recorded in the legacy array form are converted to components first: the
// encoder rejects a document that carries both forms.
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
	tools := bom.Metadata.Tools

	if tools.Tools != nil {
		converted := lo.Map(*tools.Tools, func(tool cdx.Tool, _ int) cdx.Component {
			comp := cdx.Component{
				Type:               cdx.ComponentTypeApplication,
				Name:               tool.Name,
				Version:            tool.Version,
				Hashes:             tool.Hashes,
				ExternalReferences: tool.ExternalReferences,
			}
			if tool.Vendor != "" {
				comp.Manufacturer = &cdx.OrganizationalEntity{Name: tool.Vendor}
			}
			return comp
		})
		tools.Components = lo.ToPtr(append(converted, lo.FromPtr(tools.Components)...))
		tools.Tools = nil
	}

	if HasWerfTool(bom) {
		return
	}

	tools.Components = lo.ToPtr(append(lo.FromPtr(tools.Components), cdx.Component{
		Type:    cdx.ComponentTypeApplication,
		Name:    werfToolName,
		Version: version,
	}))
}

// HasWerfTool reports whether werf is recorded among the tools that produced
// bom, in either form.
func HasWerfTool(bom *cdx.BOM) bool {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Tools == nil {
		return false
	}
	tools := bom.Metadata.Tools
	return lo.ContainsBy(lo.FromPtr(tools.Components), func(comp cdx.Component) bool { return comp.Name == werfToolName }) ||
		lo.ContainsBy(lo.FromPtr(tools.Tools), func(tool cdx.Tool) bool { return tool.Name == werfToolName })
}
