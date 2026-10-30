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
	Version *int `json:"version"`
	// Bootstrap marks an image that is built to be imported from and never shipped:
	// a toolchain, a compiler, an environment nothing of which this project claims to
	// describe. Its own composition is neither converged nor published, and the files
	// an image imports from it carry no claim unless something else accounts for them.
	Bootstrap bool `json:"bootstrap,omitempty"`
	// PreparedSource marks an image that is nothing but a prepared source: it stands on
	// no base, runs nothing, and only collects files other images already answer for,
	// so that builds downstream can consume it as the pinned package it declares itself
	// to be. It is the one image allowed to take files out of a bootstrap image without
	// answering for them one by one.
	PreparedSource bool `json:"preparedSource,omitempty"`
	// BootstrapOriginals state, per bootstrap source image this recipe imports from,
	// which prepared source the files of a subtree of it were opened from and at which
	// path of that source they stand. A bootstrap image describes no composition of its
	// own, so a file taken out of it is answered for by the record of its own build or
	// by one of these bindings, and by nothing else.
	BootstrapOriginals []sbomBuildContextBootstrapOriginal       `json:"bootstrapOriginals,omitempty"`
	Stages             map[stage.StageName]sbomBuildContextStage `json:"stages"`
}

// sbomBuildContextBootstrapOriginal binds one subtree of a bootstrap source image to the
// prepared source that serves its files. The physical place of a file and its place in
// the Packet commonly differ - a toolchain installs headers of its own runtime sources
// somewhere else entirely - so the path inside the Packet is named rather than assumed,
// and equal bytes elsewhere in it bind nothing.
type sbomBuildContextBootstrapOriginal struct {
	// SourceImage is the logical werf image name of the bootstrap source.
	SourceImage string `json:"sourceImage"`
	// PackageName and PackageVersion name one of the prepared sources the source
	// image's own receipt pins, or one its own recipe declares its stages compile;
	// nothing else may be named here.
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	// Root is the absolute path of the source image the mapping covers, file or
	// directory. The most specific root wins where several of them cover a file.
	Root string `json:"root"`
	// OriginalPath is where the contents of Root stand inside the Packet, "." naming
	// its root.
	OriginalPath string `json:"originalPath"`
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
	// Kind tells a dependency of the project from the project itself. Empty and
	// "dependency" are the same thing; "project" names the stage's own sources,
	// which no lockfile pins and which carry none of the fields below.
	Kind string `json:"kind,omitempty"`
	// Locator is the lockfile `resolved` value of the dependency, verbatim.
	Locator string `json:"locator,omitempty"`
	// InstalledPath is where the package is installed in the produced stage: under a
	// node_modules directory of the project for a dependency, the project root
	// itself for the project.
	InstalledPath  string `json:"installedPath"`
	PackageName    string `json:"packageName,omitempty"`
	PackageVersion string `json:"packageVersion,omitempty"`
}

// project reports whether the binding names the stage's own sources.
func (binding sbomBuildContextGitSource) project() bool {
	return binding.Kind == sbomBuildContextGitProject
}

const (
	sbomBuildContextGitDependency = "dependency"
	sbomBuildContextGitProject    = "project"
)

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
	// A bootstrap image publishes nothing of itself, but its stages are built like any
	// other: the compilers running there are instrumented ones, and they need the same
	// producer context stating which prepared sources they compile.
	if declaration.Bootstrap && len(declaration.BootstrapOriginals) > 0 {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: a bootstrap image states the originals of nothing")
	}
	// The two say opposite things about the same image: one describes nothing of itself,
	// the other is itself what a description names.
	if declaration.Bootstrap && declaration.PreparedSource {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: an image is either a bootstrap image or a prepared source, not both")
	}
	// A prepared source runs nothing, so there is no stage for a compiler context.
	if declaration.PreparedSource && len(declaration.Stages) > 0 {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: a prepared source image declares no stages")
	}
	if !declaration.Bootstrap && !declaration.PreparedSource && len(declaration.Stages) == 0 && len(declaration.BootstrapOriginals) == 0 {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: at least one stage is required")
	}
	if err := validateSBOMBuildContextBootstrapOriginals(declaration.BootstrapOriginals); err != nil {
		return nil, fmt.Errorf("parse SBOM build context declaration: invalid: %w", err)
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

func validateSBOMBuildContextBootstrapOriginals(declared []sbomBuildContextBootstrapOriginal) error {
	roots := make(map[string]bool, len(declared))
	for i, mapping := range declared {
		for _, field := range []struct{ name, value string }{
			{"sourceImage", mapping.SourceImage}, {"packageName", mapping.PackageName},
			{"packageVersion", mapping.PackageVersion}, {"root", mapping.Root}, {"originalPath", mapping.OriginalPath},
		} {
			if err := validateSBOMBuildContextField(field.name, field.value); err != nil {
				return fmt.Errorf("bootstrapOriginal %d: %w", i, err)
			}
		}
		if !path.IsAbs(mapping.Root) || path.Clean(mapping.Root) != mapping.Root {
			return fmt.Errorf("bootstrapOriginal %d: root must be a clean absolute path", i)
		}
		if !cleanRelativeOriginalPath(mapping.OriginalPath) {
			return fmt.Errorf("bootstrapOriginal %d: originalPath %q is not a path inside the prepared source", i, mapping.OriginalPath)
		}
		if roots[mapping.SourceImage+"\x00"+mapping.Root] {
			return fmt.Errorf("bootstrapOriginal %d: root %q of %s is declared more than once", i, mapping.Root, mapping.SourceImage)
		}
		roots[mapping.SourceImage+"\x00"+mapping.Root] = true
	}

	return nil
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
		switch binding.Kind {
		case "", sbomBuildContextGitDependency, sbomBuildContextGitProject:
		default:
			return fmt.Errorf("gitSource %d: kind %q is not a kind of Git source", i, binding.Kind)
		}
		required := []struct{ name, value string }{{"to", binding.To}, {"installedPath", binding.InstalledPath}}
		if !binding.project() {
			required = append(required,
				struct{ name, value string }{"locator", binding.Locator},
				struct{ name, value string }{"packageName", binding.PackageName},
				struct{ name, value string }{"packageVersion", binding.PackageVersion},
			)
		}
		for _, field := range required {
			if err := validateSBOMBuildContextField(field.name, field.value); err != nil {
				return fmt.Errorf("gitSource %d: %w", i, err)
			}
		}
		for _, field := range []struct{ name, value string }{{"to", binding.To}, {"installedPath", binding.InstalledPath}} {
			if !path.IsAbs(field.value) || path.Clean(field.value) != field.value {
				return fmt.Errorf("gitSource %d: %s must be a clean absolute path", i, field.name)
			}
		}
		if binding.project() {
			// The project is named by the commit its own mapping is pinned to, so
			// a lock entry here would be a second, unverifiable name for it.
			for _, field := range []struct{ name, value string }{
				{"locator", binding.Locator}, {"packageName", binding.PackageName}, {"packageVersion", binding.PackageVersion},
			} {
				if field.value != "" {
					return fmt.Errorf("gitSource %d: a project names itself by its commit, not by %s", i, field.name)
				}
			}
			// A dependency is delivered by its mapping and installed elsewhere by the
			// package manager, but the project is its own sources: the place the
			// mapping adds them is the place they are.
			if binding.InstalledPath != binding.To {
				return fmt.Errorf("gitSource %d: a project is installed where its mapping adds it, not at %s", i, binding.InstalledPath)
			}
		} else {
			if !sbomBuildContextGitLocatorRegexp.MatchString(binding.Locator) {
				return fmt.Errorf("gitSource %d: locator %q does not pin a repository to a full commit", i, binding.Locator)
			}
			// The installed path is the physical package directory of that very
			// package, so a binding cannot name the install of one package as
			// another one.
			if !strings.HasSuffix(binding.InstalledPath, "/node_modules/"+binding.PackageName) {
				return fmt.Errorf("gitSource %d: installedPath %q is not the node_modules directory of %s", i, binding.InstalledPath, binding.PackageName)
			}
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
