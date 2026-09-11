package managedinput

import (
	"path"
	"slices"

	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

type inputResolver struct {
	inputType     config.PackagesDirectiveType
	catalogerName string
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
		if eco.CatalogerName == "" {
			continue
		}
		// No syft cataloger is derived for os-pm; its runtime index is collected separately.
		if t == config.PackagesDirectiveTypeOSPM {
			continue
		}
		built = append(built, inputResolver{
			inputType:     eco.Type,
			catalogerName: eco.CatalogerName,
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

		cataloger := scanner.Cataloger{
			Name:        res.catalogerName,
			SourcePaths: []string{path.Join(directive.FileBased.Workdir, directive.FileBased.Spec)},
		}
		// The lock is optional: a spec with no dependencies (e.g. a go module without a
		// go.sum) has none, and the build must not fail over its absence.
		if directive.FileBased.Lock != "" {
			cataloger.OptionalSourcePaths = []string{path.Join(directive.FileBased.Workdir, directive.FileBased.Lock)}
		}

		catalogers = append(catalogers, cataloger)
	}

	return catalogers
}
