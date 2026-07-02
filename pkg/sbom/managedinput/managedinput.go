package managedinput

import (
	"path"
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

var resolvers = []inputResolver{
	{
		inputType:     config.PackagesDirectiveTypeGoMod,
		catalogerName: "go-module-file-cataloger",
		sourcePaths: func(directive *config.PackagesDirective) []string {
			return []string{
				path.Join(directive.GoMod.Workdir, directive.GoMod.Spec),
				path.Join(directive.GoMod.Workdir, directive.GoMod.Lock),
			}
		},
	},
	{
		inputType:     config.PackagesDirectiveTypePythonUV,
		catalogerName: "python-package-cataloger",
		sourcePaths:   pythonSourcePaths,
	},
	{
		inputType:     config.PackagesDirectiveTypePythonPip,
		catalogerName: "python-package-cataloger",
		sourcePaths:   pythonSourcePaths,
	},
	{
		inputType:     config.PackagesDirectiveTypePythonPoetry,
		catalogerName: "python-package-cataloger",
		sourcePaths:   pythonSourcePaths,
	},
}

func pythonSourcePaths(d *config.PackagesDirective) []string {
	paths := []string{path.Join(d.Python.Workdir, d.Python.Spec)}
	if d.Python.Lock != "" {
		paths = append(paths, path.Join(d.Python.Workdir, d.Python.Lock))
	}
	return paths
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
