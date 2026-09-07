package cyclonedxutil

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ResolveUnknownGoVersions mutates bom in place, replacing UNKNOWN/(devel)
// versions of the main module and local replace targets with version.
func ResolveUnknownGoVersions(bom *cdx.BOM, version, modulePath string, localReplaceTargets, localReplacePaths []string) {
	if version == "" {
		return
	}

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

	match := func(c *cdx.Component) bool {
		if !isUnresolvedVersion(c.Version) {
			return false
		}
		if c.Type != cdx.ComponentTypeLibrary {
			return false
		}
		_, ok := targets[c.Name]
		return ok
	}

	patch := func(c *cdx.Component) {
		if correctName, ok := pathToModule[c.Name]; ok {
			c.Name = correctName
			c.PackageURL = fmt.Sprintf("pkg:golang/%s@%s", correctName, version)
		} else if c.PackageURL != "" {
			c.PackageURL = resolvePackageURLVersion(c.PackageURL, version)
		}
		c.Version = version
	}

	PatchComponents(bom, match, patch)
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
