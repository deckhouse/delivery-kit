package cyclonedxutil

import (
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

		component.Version = version
		if component.PackageURL != "" {
			component.PackageURL = resolvePackageURLVersion(component.PackageURL, version)
		}
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
