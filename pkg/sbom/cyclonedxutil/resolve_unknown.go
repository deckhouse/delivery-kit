package cyclonedxutil

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func ResolveUnknownGoVersions(bom *cdx.BOM, version, modulePath string, localReplaceTargets, localReplacePaths []string) *cdx.BOM {
	if bom == nil || bom.Components == nil || version == "" {
		return bom
	}

	components := *bom.Components
	if len(components) == 0 {
		return bom
	}

	// pathToModule maps filesystem paths (e.g. "./mylib") to module names (e.g. "example.com/mylib")
	// so we can fix component name and PURL when Syft used the filesystem path.
	pathToModule := make(map[string]string, len(localReplacePaths))
	for i, p := range localReplacePaths {
		if p != "" && i < len(localReplaceTargets) {
			pathToModule[p] = localReplaceTargets[i]
		}
	}

	targets := map[string]struct{}{
		modulePath:               {},
		"command-line-arguments": {},
	}
	for _, t := range localReplaceTargets {
		if t != "" {
			targets[t] = struct{}{}
		}
	}
	for _, p := range localReplacePaths {
		if p != "" {
			targets[p] = struct{}{}
		}
	}

	for i := range components {
		component := &components[i]
		if !isUnresolvedVersion(component.Version) {
			continue
		}
		if component.Type != cdx.ComponentTypeLibrary {
			continue
		}
		if _, ok := targets[component.Name]; !ok {
			continue
		}

		if correctName, ok := pathToModule[component.Name]; ok {
			component.Name = correctName
			component.PackageURL = fmt.Sprintf("pkg:golang/%s@%s", correctName, version)
		} else {
			if component.PackageURL != "" {
				component.PackageURL = resolvePackageURLVersion(component.PackageURL, version)
			}
		}

		component.Version = version
	}

	return bom
}

func isUnresolvedVersion(v string) bool {
	return v == "UNKNOWN" || v == "(devel)"
}

func resolvePackageURLVersion(purl, version string) string {
	for _, old := range []string{"@UNKNOWN", "@(devel)", "@%28devel%29"} {
		if strings.Contains(purl, old) {
			return strings.ReplaceAll(purl, old, "@"+version)
		}
	}

	if !strings.Contains(purl, "@") {
		return purl + "@" + version
	}

	return purl
}
