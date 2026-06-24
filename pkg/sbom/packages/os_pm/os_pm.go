package os_pm

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

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

	keys := make([]string, 0, len(pkgs))
	for k := range pkgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	components := make([]cdx.Component, 0, len(pkgs))
	var dependencies []cdx.Dependency

	for _, key := range keys {
		pkg := pkgs[key]
		purl := purlOf(pkg)

		comp := cdx.Component{
			BOMRef:      purl,
			Type:        cdx.ComponentTypeLibrary,
			Name:        pkg.Name,
			Version:     pkg.Version,
			Description: pkg.Description,
			PackageURL:  purl,
		}

		if pkg.License != "" {
			comp.Licenses = &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: pkg.License}}}
		}

		comp.Hashes = digestToHashes(pkg.Digest)
		comp.Properties = packageProperties(pkg)

		components = append(components, comp)

		if refs := dependencyRefs(pkg, pkgs); refs != nil {
			dependencies = append(dependencies, cdx.Dependency{Ref: purl, Dependencies: refs})
		}
	}

	bom := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components:  &components,
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}

	return bom
}

func purlOf(pkg PmPackageInfo) string {
	purl := fmt.Sprintf("pkg:generic/%s@%s", pkg.Name, pkg.Version)
	if pkg.OriginalRepo != "" {
		purl += "?repository_url=" + url.QueryEscape(pkg.OriginalRepo)
	}

	return purl
}

func digestToHashes(digest string) *[]cdx.Hash {
	alg, value, found := strings.Cut(digest, ":")
	if !found || value == "" {
		return nil
	}

	var algorithm cdx.HashAlgorithm
	switch strings.ToLower(alg) {
	case "sha256":
		algorithm = cdx.HashAlgoSHA256
	case "sha512":
		algorithm = cdx.HashAlgoSHA512
	case "sha1":
		algorithm = cdx.HashAlgoSHA1
	default:
		return nil
	}

	return &[]cdx.Hash{{Algorithm: algorithm, Value: value}}
}

func packageProperties(pkg PmPackageInfo) *[]cdx.Property {
	var props []cdx.Property
	for _, arch := range pkg.Arch {
		props = append(props, cdx.Property{Name: "werf:pm:arch", Value: arch})
	}
	if pkg.Type != "" {
		props = append(props, cdx.Property{Name: "werf:pm:type", Value: pkg.Type})
	}
	if pkg.Repo != "" {
		props = append(props, cdx.Property{Name: "werf:pm:repo", Value: pkg.Repo})
	}

	if len(props) == 0 {
		return nil
	}

	return &props
}

func dependencyRefs(pkg PmPackageInfo, pkgs map[string]PmPackageInfo) *[]string {
	if len(pkg.Depends) == 0 {
		return nil
	}

	sorted := append([]string(nil), pkg.Depends...)
	sort.Strings(sorted)

	refs := make([]string, 0, len(sorted))
	for _, name := range sorted {
		if dep, ok := pkgs[name]; ok {
			refs = append(refs, purlOf(dep))
		}
	}

	if len(refs) == 0 {
		return nil
	}

	return &refs
}
