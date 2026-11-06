package gomod

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/modfile"
)

// DropUnrequiredLocalReplaces removes the components syft invents for guard directives:
// a `replace X => ./dir` with no `require X` is how a module forbids a dependency, not how
// it takes one. syft catalogs every replace, so such a module reaches the SBOM without a
// version and with nothing to resolve it against.
func DropUnrequiredLocalReplaces(bom *cdx.BOM, goModContent []byte) error {
	mod, err := modfile.Parse("go.mod", goModContent, nil)
	if err != nil {
		return fmt.Errorf("sbom: parse go.mod: %w", err)
	}

	required := make(map[string]struct{}, len(mod.Require))
	for _, req := range mod.Require {
		required[req.Mod.Path] = struct{}{}
	}

	unrequired := make(map[string]struct{})
	for _, replace := range mod.Replace {
		if !modfile.IsDirectoryPath(replace.New.Path) {
			continue
		}
		if _, ok := required[replace.Old.Path]; ok {
			continue
		}
		unrequired[replace.Old.Path] = struct{}{}
	}

	if len(unrequired) == 0 || bom.Components == nil {
		return nil
	}

	kept := (*bom.Components)[:0]
	for _, c := range *bom.Components {
		if isGolangComponent(c) {
			if _, drop := unrequired[c.Name]; drop {
				continue
			}
		}
		kept = append(kept, c)
	}
	*bom.Components = kept

	return nil
}

func isGolangComponent(c cdx.Component) bool {
	if c.PackageURL == "" {
		return false
	}
	purl, err := packageurl.FromString(c.PackageURL)
	return err == nil && purl.Type == packageurl.TypeGolang
}
