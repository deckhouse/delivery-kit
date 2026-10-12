package gomod

import (
	"fmt"

	"golang.org/x/mod/modfile"
)

type GoModInfo struct {
	ModulePath          string
	LocalReplaceTargets []string // Old.Path values (e.g. "example.com/mylib")
	LocalReplacePaths   []string // New.Path values (e.g. "./mylib") — Syft may use these as component names
}

// ParseLocalReplaces collects the modules whose version syft cannot know: the main
// module and every module replaced by a directory. A module replaced by another
// module is left out — syft catalogs it under the replacement's path and version,
// which is already correct.
func ParseLocalReplaces(goModContent []byte) (*GoModInfo, error) {
	mod, err := modfile.Parse("go.mod", goModContent, nil)
	if err != nil {
		return nil, fmt.Errorf("sbom: parse go.mod: %w", err)
	}

	if mod.Module == nil {
		return nil, fmt.Errorf("sbom: missing module directive")
	}

	info := &GoModInfo{
		ModulePath: mod.Module.Mod.Path,
	}

	for _, replace := range mod.Replace {
		if !modfile.IsDirectoryPath(replace.New.Path) {
			continue
		}

		info.LocalReplaceTargets = append(info.LocalReplaceTargets, replace.Old.Path)
		info.LocalReplacePaths = append(info.LocalReplacePaths, replace.New.Path)
	}

	return info, nil
}
