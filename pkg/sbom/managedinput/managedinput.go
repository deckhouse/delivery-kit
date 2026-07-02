package managedinput

import (
	"path"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

type inputResolver struct {
	inputType     config.PackagesDirectiveType
	catalogerName string
	sourcePaths   func(directive *config.PackagesDirective) []string
}

var resolvers = buildResolvers()

func buildResolvers() []inputResolver {
	ecosystems := config.Ecosystems()
	types := make([]config.PackagesDirectiveType, 0, len(ecosystems))
	for t := range ecosystems {
		types = append(types, t)
	}
	slices.Sort(types)

	built := make([]inputResolver, 0, len(types))
	for _, t := range types {
		eco := ecosystems[t]
		built = append(built, inputResolver{
			inputType:     eco.Type,
			catalogerName: eco.CatalogerName,
			sourcePaths: func(d *config.PackagesDirective) []string {
				paths := []string{path.Join(d.FileBased.Workdir, d.FileBased.Spec)}
				if d.FileBased.Lock != "" {
					paths = append(paths, path.Join(d.FileBased.Workdir, d.FileBased.Lock))
				}
				return paths
			},
		})
	}
	return built
}

func ToCatalogers(packages []*config.PackagesDirective) []scanner.Cataloger {
	var catalogers []scanner.Cataloger

	for _, directive := range packages {
		res, found := lo.Find(resolvers, func(r inputResolver) bool {
			return r.inputType == directive.Type
		})
		if !found {
			continue
		}

		catalogers = append(catalogers, scanner.Cataloger{
			Name:        res.catalogerName,
			SourcePaths: res.sourcePaths(directive),
		})
	}

	return catalogers
}

func FilterBOMBySourcePaths(bom *cdx.BOM, catalogers []scanner.Cataloger) {
	if bom == nil || bom.Components == nil || len(catalogers) == 0 {
		return
	}

	catalogerNames := make(map[string]struct{})
	allowedPaths := make(map[string]struct{})
	for _, cat := range catalogers {
		catalogerNames[cat.Name] = struct{}{}
		for _, p := range cat.SourcePaths {
			allowedPaths[p] = struct{}{}
		}
	}

	filtered := lo.Filter(*bom.Components, func(comp cdx.Component, _ int) bool {
		if !componentFoundByCatalogers(comp, catalogerNames) {
			return false
		}
		return componentMatchesAllowedPaths(comp, allowedPaths)
	})

	*bom.Components = filtered
}

func componentFoundByCatalogers(comp cdx.Component, catalogerNames map[string]struct{}) bool {
	if comp.Properties == nil {
		return false
	}
	for _, prop := range *comp.Properties {
		if prop.Name == "syft:package:foundBy" {
			_, ok := catalogerNames[prop.Value]
			return ok
		}
	}
	return false
}

func componentMatchesAllowedPaths(comp cdx.Component, allowedPaths map[string]struct{}) bool {
	if comp.Properties == nil {
		return false
	}
	for _, prop := range *comp.Properties {
		if !strings.HasPrefix(prop.Name, "syft:location:") || !strings.HasSuffix(prop.Name, ":path") {
			continue
		}
		if _, ok := allowedPaths[prop.Value]; ok {
			return true
		}
	}
	return false
}
