package os_pm

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"

	"github.com/werf/werf/v2/pkg/sbom/cpe"
)

const (
	catalogerName      = "pm-cataloger"
	artifactTypeBinary = "binary"
	propFoundBy        = "werf:package:foundBy"
	propArtifactType   = "werf:package:type"
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

type pmLockFile struct {
	Packages map[string]PmPackageInfo `json:"packages"`
}

func ParsePmLockJSON(data []byte) (map[string]PmPackageInfo, error) {
	var lock pmLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pm lock: %w", err)
	}

	return lock.Packages, nil
}

func ConvertToCycloneDX(pkgs map[string]PmPackageInfo, containerFactoryVersion string) *cdx.BOM {
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
		purl := purlOf(pkg, containerFactoryVersion)

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
		setCPEEvidence(&comp, pkg)

		components = append(components, comp)

		if refs := dependencyRefs(pkg, pkgs, containerFactoryVersion); refs != nil {
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

func purlOf(pkg PmPackageInfo, containerFactoryVersion string) string {
	return packageurl.NewPackageURL(
		"generic", "",
		pkg.Name, pkg.Version,
		packageurl.Qualifiers{
			{Key: "containerFactoryVersion", Value: containerFactoryVersion},
		},
		"",
	).ToString()
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
	props := []cdx.Property{
		{Name: propFoundBy, Value: catalogerName},
		{Name: propArtifactType, Value: artifactTypeBinary},
	}
	for _, arch := range pkg.Arch {
		props = append(props, cdx.Property{Name: "werf:pm:arch", Value: arch})
	}
	if pkg.Type != "" {
		props = append(props, cdx.Property{Name: "werf:pm:type", Value: pkg.Type})
	}
	if pkg.Repo != "" {
		props = append(props, cdx.Property{Name: "werf:pm:repo", Value: pkg.Repo})
	}

	return &props
}

func dependencyRefs(pkg PmPackageInfo, pkgs map[string]PmPackageInfo, containerFactoryVersion string) *[]string {
	if len(pkg.Depends) == 0 {
		return nil
	}

	sorted := append([]string(nil), pkg.Depends...)
	sort.Strings(sorted)

	refs := make([]string, 0, len(sorted))
	for _, name := range sorted {
		if dep, ok := pkgs[name]; ok {
			refs = append(refs, purlOf(dep, containerFactoryVersion))
		}
	}

	if len(refs) == 0 {
		return nil
	}

	return &refs
}

// setCPEEvidence attaches the most specific inferred CPE to component.cpe and
// records the remaining candidates as identity evidence. pm binaries are typed
// pkg:generic, which vulnerability scanners match through CPE rather than purl.
func setCPEEvidence(comp *cdx.Component, pkg PmPackageInfo) {
	candidates := cpe.GenerateForPmPackage(cpe.PackageInput{
		Name:         pkg.Name,
		Version:      pkg.Version,
		OriginalRepo: pkg.OriginalRepo,
		Repo:         pkg.Repo,
	})
	if len(candidates) == 0 {
		return
	}

	comp.CPE = candidates[0].String()

	if len(candidates) == 1 {
		return
	}

	evidenceItems := make([]cdx.EvidenceIdentity, 0, len(candidates)-1)
	for _, candidate := range candidates[1:] {
		confidence := float32(0.5)
		methods := []cdx.EvidenceIdentityMethod{{
			Technique:  cdx.EvidenceIdentityTechniqueOther,
			Confidence: &confidence,
			Value:      candidate.String(),
		}}
		evidenceItems = append(evidenceItems, cdx.EvidenceIdentity{
			Field:      cdx.EvidenceIdentityFieldTypeCPE,
			Confidence: &confidence,
			Methods:    &methods,
		})
	}

	comp.Evidence = &cdx.Evidence{Identity: &evidenceItems}
}
