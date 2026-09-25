package managedinput

import (
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var syftLicensePatterns = []string{"licen[cs]e*", "unlicen[cs]e*", "mit-licen[cs]e*", "copying*", "notice*"}

func nodeModulesEnrichment(root string) *scanner.Enrichment {
	return &scanner.Enrichment{
		Kind:             scanner.EnrichmentKindDir,
		Root:             root,
		FileNamePatterns: []string{"package.json"},
	}
}

// goModCacheEnrichment is the unresolved plan ToCatalogers emits: the module cache root
// depends on the image environment and is filled in at materialization time.
func goModCacheEnrichment(lockPath string, directiveEnv ...map[string]string) *scanner.Enrichment {
	e := &scanner.Enrichment{
		Kind:             scanner.EnrichmentKindGoModCache,
		FileNamePatterns: syftLicensePatterns,
		LockPath:         lockPath,
	}
	if len(directiveEnv) > 0 {
		e.DirectiveEnv = directiveEnv[0]
	}
	return e
}
