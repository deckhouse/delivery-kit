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
	filterMode    scanner.CatalogerFilterMode
	sourcePaths   func(directive *config.PackagesDirective) []string
	workdir       func(directive *config.PackagesDirective) string
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
		filterMode := scanner.CatalogerFilterExactPath
		if eco.UseWorkdirFilter {
			filterMode = scanner.CatalogerFilterWorkdirPrefix
		}
		built = append(built, inputResolver{
			inputType:     eco.Type,
			catalogerName: eco.CatalogerName,
			filterMode:    filterMode,
			sourcePaths: func(d *config.PackagesDirective) []string {
				paths := []string{path.Join(d.FileBased.Workdir, d.FileBased.Spec)}
				if d.FileBased.Lock != "" {
					paths = append(paths, path.Join(d.FileBased.Workdir, d.FileBased.Lock))
				}
				return paths
			},
			workdir: func(d *config.PackagesDirective) string {
				return d.FileBased.Workdir
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
			FilterMode:  res.filterMode,
			SourcePaths: res.sourcePaths(directive),
			Workdir:     res.workdir(directive),
		})
	}

	return catalogers
}

func FilterBOMBySourcePaths(bom *cdx.BOM, catalogers []scanner.Cataloger) {
	if bom == nil || bom.Components == nil || len(catalogers) == 0 {
		return
	}

	type catalogerFilter struct {
		name       string
		filterMode scanner.CatalogerFilterMode
		paths      map[string]struct{}
		workdir    string
	}

	filters := make([]catalogerFilter, 0, len(catalogers))
	for _, cat := range catalogers {
		paths := make(map[string]struct{}, len(cat.SourcePaths))
		for _, p := range cat.SourcePaths {
			paths[p] = struct{}{}
		}
		filters = append(filters, catalogerFilter{
			name:       cat.Name,
			filterMode: cat.FilterMode,
			paths:      paths,
			workdir:    cat.Workdir,
		})
	}

	filtered := lo.Filter(*bom.Components, func(comp cdx.Component, _ int) bool {
		for _, f := range filters {
			if !componentFoundByCataloger(comp, f.name) {
				continue
			}
			if f.filterMode == scanner.CatalogerFilterWorkdirPrefix {
				if componentMatchesWorkdirPrefix(comp, f.workdir) {
					return true
				}
			} else {
				if componentMatchesAllowedPaths(comp, f.paths) {
					return true
				}
			}
		}
		return false
	})

	*bom.Components = filtered
}

func componentFoundByCataloger(comp cdx.Component, catalogerName string) bool {
	if comp.Properties == nil {
		return false
	}
	for _, prop := range *comp.Properties {
		if prop.Name == "syft:package:foundBy" {
			return prop.Value == catalogerName
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

func componentMatchesWorkdirPrefix(comp cdx.Component, workdir string) bool {
	if comp.Properties == nil {
		return false
	}
	prefix := workdir + "/"
	for _, prop := range *comp.Properties {
		if !strings.HasPrefix(prop.Name, "syft:location:") || !strings.HasSuffix(prop.Name, ":path") {
			continue
		}
		if strings.HasPrefix(prop.Value, prefix) {
			return true
		}
	}
	return false
}
