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
	enrichment    *config.EnrichmentSource
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
			enrichment:    eco.Enrichment,
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

		workdir := directive.FileBased.Workdir
		cataloger := scanner.Cataloger{
			Name:        res.catalogerName,
			SourcePaths: []string{path.Join(workdir, directive.FileBased.Spec)},
		}

		// The lock is optional: a spec with no dependencies (e.g. a go module without a
		// go.sum) has none, and the build must not fail over its absence.
		var lockPath string
		if directive.FileBased.Lock != "" {
			lockPath = path.Join(workdir, directive.FileBased.Lock)
			cataloger.OptionalSourcePaths = []string{lockPath}
		}

		cataloger.Enrichment = toEnrichment(res.enrichment, workdir, lockPath)

		catalogers = append(catalogers, cataloger)
	}

	return catalogers
}

// toEnrichment turns the ecosystem's enrichment source into a scan plan. A workdir root
// is resolved here; the Go module cache root depends on the image environment and is
// resolved at materialization time (see ResolveEnrichmentRoot), so it stays empty here
// and does not feed the scan cache key.
func toEnrichment(src *config.EnrichmentSource, workdir, lockPath string) *scanner.Enrichment {
	if src == nil {
		return nil
	}

	switch src.Root {
	case config.EnrichmentRootWorkdir:
		return &scanner.Enrichment{
			Kind:             scanner.EnrichmentKindDir,
			Root:             path.Join(workdir, src.Path),
			FileNamePatterns: src.FileNamePatterns,
		}
	case config.EnrichmentRootGoModCache:
		if lockPath == "" {
			return nil
		}
		return &scanner.Enrichment{
			Kind:             scanner.EnrichmentKindGoModCache,
			FileNamePatterns: src.FileNamePatterns,
			LockPath:         lockPath,
		}
	default:
		panic("unsupported enrichment root " + string(src.Root))
	}
}

// ResolveEnrichmentRoot fills in an enrichment root that depends on the image
// environment. imageEnv is the image config environment (KEY=VALUE entries).
func ResolveEnrichmentRoot(enrichment *scanner.Enrichment, imageEnv []string) {
	if enrichment == nil || enrichment.Kind != scanner.EnrichmentKindGoModCache {
		return
	}
	enrichment.Root = GoModCacheDir(imageEnv)
}
