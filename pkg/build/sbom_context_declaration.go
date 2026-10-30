package build

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	sigsjson "sigs.k8s.io/json"

	"github.com/werf/werf/v3/pkg/build/stage"
)

// sbomBuildContextLabel marks an image whose config declares the producer intent
// of its SBOM build context: which prepared sources a stage consumes and which
// one of them is the subject of the stage.
const sbomBuildContextLabel = stage.SBOMBuildContextLabel

// sbomBuildContextVersion is the only declaration version understood here.
const sbomBuildContextVersion = 1

// sbomBuildContextDeclaration is the producer intent only: it never carries
// resolved references, digests or platforms of the build context itself.
type sbomBuildContextDeclaration struct {
	Version *int                                      `json:"version"`
	Stages  map[stage.StageName]sbomBuildContextStage `json:"stages"`
}

type sbomBuildContextStage struct {
	// Subject indexes Packages: the stage declares that prepared source as the
	// thing it builds. There is no default, a missing subject is an error.
	Subject        *int                      `json:"subject"`
	Packages       []sbomBuildContextPackage `json:"packages"`
	GoEmbed        []sbomBuildContextGoEmbed `json:"goEmbed,omitempty"`
	WebpackSources bool                      `json:"webpackSources,omitempty"`
	// PrebuiltAssets bind a file installed in this stage to the instrumented rebuild
	// that produced it. The binding is the producer's claim about its own recipe; that
	// the named image really emitted those bytes, and that the installed file really is
	// them, is the consumer's to verify.
	PrebuiltAssets []sbomBuildContextPrebuilt `json:"prebuiltAssets,omitempty"`
	// GitSources bind a Node dependency a lockfile pins to a Git commit to the git
	// mapping of this very config that DK fetches that commit through. The binding is
	// the producer's claim about its own recipe; the verification that the mapping is
	// that repository at that commit, and that the commit holds the named package, is
	// the consumer's.
	GitSources []sbomBuildContextGitSource `json:"gitSources,omitempty"`
}

type sbomBuildContextGitSource struct {
	// To is the `to` path of the git mapping, which names it within the config.
	To string `json:"to"`
	// Locator is the lockfile `resolved` value of the dependency, verbatim.
	Locator string `json:"locator"`
	// InstalledPath is where the package is installed in the produced stage, under a
	// node_modules directory of the project.
	InstalledPath  string `json:"installedPath"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
}

// sbomBuildContextPrebuilt names one file of a dependency that was built elsewhere,
// and the proof of the rebuild that observed what went into it.
type sbomBuildContextPrebuilt struct {
	// SourceImage is a logical werf image name of the instrumented rebuild.
	SourceImage string `json:"sourceImage"`
	// ProofPath is where that rebuild's proof stands in its own image.
	ProofPath string `json:"proofPath"`
	// AssetPath is the proof row of the one file this binding delivers, relative to
	// the output root that proof covers.
	AssetPath string `json:"assetPath"`
	// InstalledPath is where that very file stands in this stage, under a
	// node_modules directory of the project.
	InstalledPath string `json:"installedPath"`
}

type sbomBuildContextGoEmbed struct {
	SourceImage string `json:"sourceImage"`
	SourceRoot  string `json:"sourceRoot"`
	TargetRoot  string `json:"targetRoot"`
	ProofPath   string `json:"proofPath"`
}

type sbomBuildContextPackage struct {
	// SourceImage is a logical werf image name of the prepared source, not a
	// rendered reference: resolving it stays with the caller.
	SourceImage    string `json:"sourceImage"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	PackageType    string `json:"packageType"`
	// SourcePlatform is always explicit, never inferred from host or target.
	SourcePlatform string `json:"sourcePlatform"`
}

var sbomBuildContextStageNames = []stage.StageName{stage.BeforeInstall, stage.Install, stage.BeforeSetup, stage.Setup}

var sbomBuildContextPlatformRegexp = regexp.MustCompile(`^linux/[a-z0-9]+(/[a-z0-9]+)?$`)

// sbomBuildContextGitLocatorRegexp is a Git dependency pinned to a full commit. A branch,
// a tag or a short commit names no bytes and is not a locator this declaration carries.
var sbomBuildContextGitLocatorRegexp = regexp.MustCompile(`^git\+(https|ssh)://[^\s#]+#[0-9a-f]{40}$`)

func parseSBOMBuildContextDeclaration(data []byte) (*sbomBuildContextDeclaration, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("parse SBOM build context declaration: no data")
	}
	// The JSON decoder silently replaces invalid UTF-8 with U+FFFD, so reject it here.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: data is not valid UTF-8")
	}

	var declaration sbomBuildContextDeclaration
	strictErrs, err := sigsjson.UnmarshalStrict(data, &declaration)
	if err != nil {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: %w", err)
	}
	if len(strictErrs) > 0 {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: %w", errors.Join(strictErrs...))
	}

	if declaration.Version == nil {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: version is required")
	}
	if *declaration.Version != sbomBuildContextVersion {
		return nil, fmt.Errorf("parse SBOM build context declaration: unsupported version %d", *declaration.Version)
	}
	if len(declaration.Stages) == 0 {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: at least one stage is required")
	}

	var raw struct {
		Stages map[string]map[string]json.RawMessage `json:"stages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	for stageName, fields := range raw.Stages {
		if value, present := fields["webpackSources"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("parse SBOM build context declaration: invalid: stage %q: webpackSources must be a boolean", stageName)
		}
		if value, present := fields["goEmbed"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("parse SBOM build context declaration: invalid: stage %q: goEmbed must be an array", stageName)
		}
		if value, present := fields["gitSources"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("parse SBOM build context declaration: invalid: stage %q: gitSources must be an array", stageName)
		}
		if value, present := fields["prebuiltAssets"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("parse SBOM build context declaration: invalid: stage %q: prebuiltAssets must be an array", stageName)
		}
	}

	for _, stageName := range slices.Sorted(maps.Keys(declaration.Stages)) {
		if !slices.Contains(sbomBuildContextStageNames, stageName) {
			return nil, fmt.Errorf("parse SBOM build context declaration: invalid: stage %q is not allowed", stageName)
		}
		if err := validateSBOMBuildContextStage(declaration.Stages[stageName]); err != nil {
			return nil, fmt.Errorf("parse SBOM build context declaration: invalid: stage %q: %w", stageName, err)
		}
	}

	return &declaration, nil
}

func validateSBOMBuildContextStage(declared sbomBuildContextStage) error {
	if len(declared.Packages) == 0 {
		return fmt.Errorf("at least one package is required")
	}

	sourceImages := make(map[string]bool, len(declared.Packages))
	for i, pkg := range declared.Packages {
		fields := []struct {
			name  string
			value string
		}{
			{"sourceImage", pkg.SourceImage},
			{"packageName", pkg.PackageName},
			{"packageVersion", pkg.PackageVersion},
			{"packageType", pkg.PackageType},
			{"sourcePlatform", pkg.SourcePlatform},
		}
		for _, field := range fields {
			if err := validateSBOMBuildContextField(field.name, field.value); err != nil {
				return fmt.Errorf("package %d: %w", i, err)
			}
		}
		if !sbomBuildContextPlatformRegexp.MatchString(pkg.SourcePlatform) {
			return fmt.Errorf("package %d: sourcePlatform %q is not a canonical linux platform", i, pkg.SourcePlatform)
		}
		if sourceImages[pkg.SourceImage] {
			return fmt.Errorf("package %d: sourceImage %q is declared more than once", i, pkg.SourceImage)
		}
		sourceImages[pkg.SourceImage] = true
	}

	for i, binding := range declared.GoEmbed {
		if err := validateSBOMBuildContextField("sourceImage", binding.SourceImage); err != nil {
			return fmt.Errorf("goEmbed %d: %w", i, err)
		}
		for _, field := range []struct{ name, value string }{{"sourceRoot", binding.SourceRoot}, {"targetRoot", binding.TargetRoot}, {"proofPath", binding.ProofPath}} {
			if err := validateSBOMBuildContextField(field.name, field.value); err != nil {
				return fmt.Errorf("goEmbed %d: %w", i, err)
			}
			if !path.IsAbs(field.value) || path.Clean(field.value) != field.value {
				return fmt.Errorf("goEmbed %d: %s must be a clean absolute path", i, field.name)
			}
		}
	}

	// A Git original is named in the private webpack originals manifest and nowhere
	// else, so a binding without that manifest could prove nothing.
	if len(declared.GitSources) > 0 && !declared.WebpackSources {
		return fmt.Errorf("gitSources require webpackSources")
	}

	// The delivered composition is only written out beside the originals manifest,
	// and the installed file is only held against a digest that manifest states.
	if len(declared.PrebuiltAssets) > 0 && !declared.WebpackSources {
		return fmt.Errorf("prebuiltAssets require webpackSources")
	}

	delivered := make(map[string]bool, len(declared.PrebuiltAssets))
	for i, binding := range declared.PrebuiltAssets {
		for _, field := range []struct{ name, value string }{
			{"sourceImage", binding.SourceImage}, {"proofPath", binding.ProofPath},
			{"assetPath", binding.AssetPath}, {"installedPath", binding.InstalledPath},
		} {
			if err := validateSBOMBuildContextField(field.name, field.value); err != nil {
				return fmt.Errorf("prebuiltAsset %d: %w", i, err)
			}
		}
		for _, field := range []struct{ name, value string }{{"proofPath", binding.ProofPath}, {"installedPath", binding.InstalledPath}} {
			if !path.IsAbs(field.value) || path.Clean(field.value) != field.value {
				return fmt.Errorf("prebuiltAsset %d: %s must be a clean absolute path", i, field.name)
			}
		}
		// The asset path names a row of that proof, which states its assets relative
		// to the output root they were emitted into.
		if path.IsAbs(binding.AssetPath) || path.Clean(binding.AssetPath) != binding.AssetPath ||
			binding.AssetPath == "." || binding.AssetPath == ".." || strings.HasPrefix(binding.AssetPath, "../") || strings.Contains(binding.AssetPath, "\\") {
			return fmt.Errorf("prebuiltAsset %d: assetPath must be a clean relative path", i)
		}
		if !strings.Contains(binding.InstalledPath, "/node_modules/") {
			return fmt.Errorf("prebuiltAsset %d: installedPath %q is not installed under node_modules", i, binding.InstalledPath)
		}
		if delivered[binding.InstalledPath] {
			return fmt.Errorf("prebuiltAsset %d: installedPath %q is declared more than once", i, binding.InstalledPath)
		}
		delivered[binding.InstalledPath] = true
	}

	mappings := make(map[string]bool, len(declared.GitSources))
	installed := make(map[string]bool, len(declared.GitSources))
	for i, binding := range declared.GitSources {
		for _, field := range []struct{ name, value string }{
			{"to", binding.To}, {"locator", binding.Locator}, {"installedPath", binding.InstalledPath},
			{"packageName", binding.PackageName}, {"packageVersion", binding.PackageVersion},
		} {
			if err := validateSBOMBuildContextField(field.name, field.value); err != nil {
				return fmt.Errorf("gitSource %d: %w", i, err)
			}
		}
		for _, field := range []struct{ name, value string }{{"to", binding.To}, {"installedPath", binding.InstalledPath}} {
			if !path.IsAbs(field.value) || path.Clean(field.value) != field.value {
				return fmt.Errorf("gitSource %d: %s must be a clean absolute path", i, field.name)
			}
		}
		if !sbomBuildContextGitLocatorRegexp.MatchString(binding.Locator) {
			return fmt.Errorf("gitSource %d: locator %q does not pin a repository to a full commit", i, binding.Locator)
		}
		// The installed path is the physical package directory of that very package,
		// so a binding cannot name the install of one package as another one.
		if !strings.HasSuffix(binding.InstalledPath, "/node_modules/"+binding.PackageName) {
			return fmt.Errorf("gitSource %d: installedPath %q is not the node_modules directory of %s", i, binding.InstalledPath, binding.PackageName)
		}
		if mappings[binding.To] {
			return fmt.Errorf("gitSource %d: to %q is declared more than once", i, binding.To)
		}
		if installed[binding.InstalledPath] {
			return fmt.Errorf("gitSource %d: installedPath %q is declared more than once", i, binding.InstalledPath)
		}
		mappings[binding.To], installed[binding.InstalledPath] = true, true
	}

	if declared.Subject == nil {
		return fmt.Errorf("subject is required")
	}
	if *declared.Subject < 0 || *declared.Subject >= len(declared.Packages) {
		return fmt.Errorf("subject %d is out of range of %d packages", *declared.Subject, len(declared.Packages))
	}

	return nil
}

func validateSBOMBuildContextField(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s %q has leading or trailing whitespace", name, value)
	}
	if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s contains control characters", name)
	}

	return nil
}
