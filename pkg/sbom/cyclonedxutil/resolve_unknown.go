package cyclonedxutil

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func ResolveUnknownGoVersions(bom *cdx.BOM, version, modulePath string, localReplaceTargets []string) *cdx.BOM {
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
	for _, target := range localReplaceTargets {
		if target == "" {
			continue
		}
		targets[target] = struct{}{}
	}

	for i := range components {
		component := &components[i]
		if component.Version != "UNKNOWN" {
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

func resolvePackageURLVersion(purl, version string) string {
	if purl == "" {
		return purl
	}
	if strings.Contains(purl, "@UNKNOWN") {
		return strings.ReplaceAll(purl, "@UNKNOWN", "@"+version)
	}
	if strings.Contains(purl, "@") {
		return purl
	}

	return purl + "@" + version
}
