package os_pm

import (
	"encoding/json"
	"fmt"
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type PmPackageInfo struct {
	Name         string   `json:"name"`
	Arch         []string `json:"arch"`
	Default      bool     `json:"default"`
	Description  string   `json:"description"`
	License      string   `json:"license"`
	OriginalRepo string   `json:"originalRepo"`
	Repo         string   `json:"repo"`
	Type         string   `json:"type"`
	Version      string   `json:"version"`
	Digest       string   `json:"digest"`
	Depends      []string `json:"depends,omitempty"`
}

func ParsePmInstalledJSON(data []byte) (map[string]PmPackageInfo, error) {
	var result map[string]PmPackageInfo
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse pm info: %w", err)
	}

	return result, nil
}

func ConvertToCycloneDX(pkgs map[string]PmPackageInfo) *cdx.BOM {
	if len(pkgs) == 0 {
		return nil
	}

	components := make([]cdx.Component, 0, len(pkgs))

	keys := make([]string, 0, len(pkgs))
	for k := range pkgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		pkg := pkgs[key]
		comp := cdx.Component{
			Name:    pkg.Name,
			Version: pkg.Version,
			Type:    cdx.ComponentTypeLibrary,
		}

		if pkg.License != "" {
			license := cdx.LicenseChoice{
				License: &cdx.License{ID: pkg.License},
			}
			comp.Licenses = &cdx.Licenses{license}
		}

		purl := fmt.Sprintf("pkg:generic/%s@%s", pkg.Name, pkg.Version)
		if pkg.Repo != "" {
			purl = fmt.Sprintf("pkg:generic/%s@%s?repository_url=%s", pkg.Name, pkg.Version, pkg.Repo)
		}
		comp.PackageURL = purl
		comp.BOMRef = purl

		components = append(components, comp)
	}

	return &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components:  &components,
	}
}
