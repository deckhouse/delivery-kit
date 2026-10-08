package config

import (
	"fmt"
	"maps"
	"path"
	"strings"

	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/os_pm/metadata"
)

type PackagesDirectiveType string

const (
	PackagesDirectiveTypeOSPM           PackagesDirectiveType = "os-pm"
	PackagesDirectiveTypeGoMod          PackagesDirectiveType = "go-mod"
	PackagesDirectiveTypePythonUV       PackagesDirectiveType = "python-uv"
	PackagesDirectiveTypePythonPip      PackagesDirectiveType = "python-pip"
	PackagesDirectiveTypePythonPoetry   PackagesDirectiveType = "python-poetry"
	PackagesDirectiveTypeRustCargo      PackagesDirectiveType = "rust-cargo"
	PackagesDirectiveTypeJavaScriptNpm  PackagesDirectiveType = "javascript-npm"
	PackagesDirectiveTypeJavaScriptYarn PackagesDirectiveType = "javascript-yarn"
	PackagesDirectiveTypeJavaScriptPnpm PackagesDirectiveType = "javascript-pnpm"
	PackagesDirectiveTypeLuaRock        PackagesDirectiveType = "lua-rock"
	PackagesDirectiveTypeRubyBundler    PackagesDirectiveType = "ruby-bundler"
	PackagesDirectiveTypeRubyGemspec    PackagesDirectiveType = "ruby-gemspec"
)

type PackagesSpec struct {
	Packages []string `yaml:"spec"`
}

type FileBasedSpec struct {
	Workdir string
	Spec    string
	Lock    string
	Manager string
}

type PackageEcosystem struct {
	Type            PackagesDirectiveType
	DefaultSpecFile string
	DefaultLockFile string
	InstallCmd      func(workdir string, files FileBasedSpec, pkgs []string, env map[string]string) string
	CatalogerName   string
	// SourceLang is the source language of the packages this ecosystem installs, as
	// reported in the GOST:source_langs property. Empty when the ecosystem installs
	// packages of an arbitrary language: os-pm distributes prebuilt binaries.
	SourceLang string
	// Enrichment describes where the syft cataloger reads metadata the lock lacks (e.g.
	// licenses) from the installed packages. Nil when the cataloger has no such source.
	Enrichment *EnrichmentSource
	// InstalledCataloger is a second syft cataloger of the ecosystem, scanning the
	// manifests the install command left in the image instead of the lock. Nil unless the
	// lock cataloger alone cannot describe the ecosystem: the Ruby one reports no
	// licenses, and only the installed gemspecs carry them. The two scans are unioned per
	// purl, which merges the licenses of one into the components of the other.
	InstalledCataloger *InstalledCataloger
}

// InstalledCataloger names a syft cataloger together with the directory of installed
// package manifests it scans.
type InstalledCataloger struct {
	Name   string
	Source EnrichmentSource
}

// EnrichmentRoot tells how the enrichment root is located in the image.
type EnrichmentRoot string

const (
	// EnrichmentRootWorkdir: Path is relative to the directive workdir (node_modules); the
	// whole directory is copied.
	EnrichmentRootWorkdir EnrichmentRoot = "workdir"
	// EnrichmentRootGoModCache: the Go module cache, $GOMODCACHE or $GOPATH/pkg/mod resolved
	// from the image environment; Path is unused. Only the directories of the modules
	// listed in go.sum are copied, since the whole cache is the image's entire dependency
	// source tree.
	EnrichmentRootGoModCache EnrichmentRoot = "go-mod-cache"
	// EnrichmentRootGemHome: the directory RubyGems installs into, $BUNDLE_PATH or
	// $GEM_HOME resolved from the image environment, else the interpreter default;
	// Path is unused.
	EnrichmentRootGemHome EnrichmentRoot = "gem-home"
)

// EnrichmentSource is what a syft cataloger reads, next to the lock it parsed, to enrich
// lock-derived components with metadata the lock itself lacks. It is copied from the
// built image into the targeted scan so the directory scan yields the same metadata the
// full-image scan did. Only files matching FileNamePatterns are copied.
type EnrichmentSource struct {
	Root EnrichmentRoot
	// Path is the workdir-relative directory for EnrichmentRootWorkdir.
	Path string
	// FileNamePatterns are case-insensitive shell patterns of the files the cataloger
	// reads inside the root, e.g. package.json or LICENSE*.
	FileNamePatterns []string
}

// syftLicenseFileNamePatterns mirrors the file names syft's license detector accepts
// (internal/licenses names.go): LICENSE and its British spelling, UNLICENSE, MIT-LICENSE,
// COPYING and NOTICE, with any extension and case.
var syftLicenseFileNamePatterns = []string{"licen[cs]e*", "unlicen[cs]e*", "mit-licen[cs]e*", "copying*", "notice*"}

// javascriptEnrichment: syft's javascript-lock-cataloger reads the license field of
// node_modules/<pkg>/package.json for every package it found in the lock.
var javascriptEnrichment = EnrichmentSource{
	Root:             EnrichmentRootWorkdir,
	Path:             "node_modules",
	FileNamePatterns: []string{"package.json"},
}

// rubyInstalledGemspecs: syft's ruby-installed-gemspec-cataloger reads the gemspec
// RubyGems writes under specifications/ for every installed gem, which is the only place
// the licenses of a bundle are recorded.
var rubyInstalledGemspecs = InstalledCataloger{
	Name: "ruby-installed-gemspec-cataloger",
	Source: EnrichmentSource{
		Root:             EnrichmentRootGemHome,
		FileNamePatterns: []string{"*.gemspec"},
	},
}

var ecosystems = map[PackagesDirectiveType]PackageEcosystem{
	PackagesDirectiveTypeGoMod: {
		Type:            PackagesDirectiveTypeGoMod,
		DefaultSpecFile: "go.mod",
		DefaultLockFile: "go.sum",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s mod download", managerBin(files, "go")), env)
		},
		CatalogerName: "go-module-file-cataloger",
		SourceLang:    "Go",
		Enrichment: &EnrichmentSource{
			Root:             EnrichmentRootGoModCache,
			FileNamePatterns: syftLicenseFileNamePatterns,
		},
	},
	PackagesDirectiveTypePythonUV: {
		Type:            PackagesDirectiveTypePythonUV,
		DefaultSpecFile: "pyproject.toml",
		DefaultLockFile: "uv.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s sync --frozen", managerBin(files, "uv")), env)
		},
		CatalogerName: "python-package-cataloger",
		SourceLang:    "Python",
	},
	PackagesDirectiveTypePythonPip: {
		Type:            PackagesDirectiveTypePythonPip,
		DefaultSpecFile: "requirements.txt",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s install --no-cache-dir -r %q", managerBin(files, "python3 -P -m pip"), files.Spec), env)
		},
		CatalogerName: "python-package-cataloger",
		SourceLang:    "Python",
	},
	PackagesDirectiveTypePythonPoetry: {
		Type:            PackagesDirectiveTypePythonPoetry,
		DefaultSpecFile: "pyproject.toml",
		DefaultLockFile: "poetry.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s sync --no-root", managerBin(files, "poetry")), env)
		},
		CatalogerName: "python-package-cataloger",
		SourceLang:    "Python",
	},
	PackagesDirectiveTypeRustCargo: {
		Type:            PackagesDirectiveTypeRustCargo,
		DefaultSpecFile: "Cargo.toml",
		DefaultLockFile: "Cargo.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s fetch", managerBin(files, "cargo")), env)
		},
		CatalogerName: "rust-cargo-lock-cataloger",
		SourceLang:    "Rust",
	},
	PackagesDirectiveTypeJavaScriptNpm: {
		Type:            PackagesDirectiveTypeJavaScriptNpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "package-lock.json",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s ci", managerBin(files, "npm")), env)
		},
		CatalogerName: "javascript-lock-cataloger",
		SourceLang:    "JavaScript",
		Enrichment:    &javascriptEnrichment,
	},
	PackagesDirectiveTypeJavaScriptYarn: {
		Type:            PackagesDirectiveTypeJavaScriptYarn,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "yarn.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s install --frozen-lockfile", managerBin(files, "yarn")), env)
		},
		CatalogerName: "javascript-lock-cataloger",
		SourceLang:    "JavaScript",
		Enrichment:    &javascriptEnrichment,
	},
	PackagesDirectiveTypeJavaScriptPnpm: {
		Type:            PackagesDirectiveTypeJavaScriptPnpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "pnpm-lock.yaml",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s install --frozen-lockfile", managerBin(files, "pnpm")), env)
		},
		CatalogerName: "javascript-lock-cataloger",
		SourceLang:    "JavaScript",
		Enrichment:    &javascriptEnrichment,
	},
	PackagesDirectiveTypeLuaRock: {
		Type:            PackagesDirectiveTypeLuaRock,
		DefaultSpecFile: "",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s install --only-deps %q", managerBin(files, "luarocks"), files.Spec), env)
		},
		CatalogerName: "lua-rock-cataloger",
		SourceLang:    "Lua",
	},
	PackagesDirectiveTypeRubyBundler: {
		Type:            PackagesDirectiveTypeRubyBundler,
		DefaultSpecFile: "Gemfile",
		DefaultLockFile: "Gemfile.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			defaults := map[string]string{"BUNDLE_FROZEN": "true"}
			if files.Spec != "Gemfile" {
				defaults["BUNDLE_GEMFILE"] = files.Spec
			}
			return formatWorkdirCommand(workdir, fmt.Sprintf("%s install", managerBin(files, "bundle")), withDefaultEnv(env, defaults))
		},
		CatalogerName:      "ruby-gemfile-cataloger",
		SourceLang:         "Ruby",
		InstalledCataloger: &rubyInstalledGemspecs,
	},
	PackagesDirectiveTypeRubyGemspec: {
		Type:            PackagesDirectiveTypeRubyGemspec,
		DefaultSpecFile: "",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			gem := managerBin(files, "gem")
			artifact := path.Join("/tmp", strings.TrimSuffix(path.Base(files.Spec), ".gemspec")+".gem")
			return formatWorkdirCommands(workdir, []string{
				fmt.Sprintf("%s build %q -o %q", gem, files.Spec, artifact),
				fmt.Sprintf("%s install --no-document %q", gem, artifact),
			}, env)
		},
		CatalogerName:      "ruby-gemspec-cataloger",
		SourceLang:         "Ruby",
		InstalledCataloger: &rubyInstalledGemspecs,
	},
	PackagesDirectiveTypeOSPM: {
		Type:            PackagesDirectiveTypeOSPM,
		DefaultSpecFile: "",
		DefaultLockFile: "",
		CatalogerName:   metadata.CatalogerName,
		InstallCmd: func(_ string, _ FileBasedSpec, pkgs []string, env map[string]string) string {
			return formatInstallCommand(pkgs, env)
		},
	},
}

// Ecosystems returns a defensive copy of the package ecosystems registry.
func Ecosystems() map[PackagesDirectiveType]PackageEcosystem {
	return maps.Clone(ecosystems)
}

type PackagesDirective struct {
	Type      PackagesDirectiveType
	FileBased FileBasedSpec
	Spec      PackagesSpec
	Env       map[string]string
}

// A manager installed by a preceding entry is verified by that entry's lock file, so the
// executable is only as trustworthy as the tree it lives in: anything outside those trees,
// a bare name included, is resolved by the image and not by the configuration.
func validatePackagesManagers(packages []*PackagesDirective) error {
	var precedingWorkdirs []string

	for _, d := range packages {
		if d.FileBased.Manager == "" {
			precedingWorkdirs = appendWorkdir(precedingWorkdirs, d)
			continue
		}

		manager := d.FileBased.Manager
		if !path.IsAbs(manager) {
			manager = path.Join(d.FileBased.Workdir, manager)
		}

		if !lo.SomeBy(precedingWorkdirs, func(workdir string) bool {
			return strings.HasPrefix(manager, workdir+"/")
		}) {
			if len(precedingWorkdirs) == 0 {
				return fmt.Errorf("invalid manager %q for type %q: no preceding packages entry installs it", d.FileBased.Manager, d.Type)
			}
			return fmt.Errorf("invalid manager %q for type %q: expected a path inside the workdir of a preceding packages entry (%s)", d.FileBased.Manager, d.Type, strings.Join(precedingWorkdirs, ", "))
		}

		precedingWorkdirs = appendWorkdir(precedingWorkdirs, d)
	}

	return nil
}

func appendWorkdir(workdirs []string, d *PackagesDirective) []string {
	if d.Type == PackagesDirectiveTypeOSPM {
		return workdirs
	}

	return append(workdirs, path.Clean(d.FileBased.Workdir))
}

func (d *PackagesDirective) validate() error {
	if _, ok := ecosystems[d.Type]; !ok {
		return fmt.Errorf("unsupported packages type %q", d.Type)
	}

	switch d.Type {
	case PackagesDirectiveTypeOSPM:
		if _, ok := d.Env["PM_LOCK_FILE"]; ok {
			return fmt.Errorf("environment variable PM_LOCK_FILE is not supported for type %q; the pm SBOM state must remain at %s", d.Type, metadata.ContainerFactoryIndexPath)
		}
		if len(d.Spec.Packages) == 0 {
			return fmt.Errorf("the `spec` is required for type %q", d.Type)
		}
	default:
		if d.FileBased.Workdir == "" {
			return fmt.Errorf("the `workdir` is required for type %q", d.Type)
		}
		if d.FileBased.Spec == "" {
			return fmt.Errorf("the `spec` is required for type %q", d.Type)
		}
	}

	return nil
}
