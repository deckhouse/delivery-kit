package config

import (
	"fmt"
	"maps"
	"path"
	"strings"

	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/os_pm/metadata"
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
}

var ecosystems = map[PackagesDirectiveType]PackageEcosystem{
	PackagesDirectiveTypeGoMod: {
		Type:            PackagesDirectiveTypeGoMod,
		DefaultSpecFile: "go.mod",
		DefaultLockFile: "go.sum",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s mod download", workdir, managerBin(files, "go"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "go-module-file-cataloger",
	},
	PackagesDirectiveTypePythonUV: {
		Type:            PackagesDirectiveTypePythonUV,
		DefaultSpecFile: "pyproject.toml",
		DefaultLockFile: "uv.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s sync --frozen", workdir, managerBin(files, "uv"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPip: {
		Type:            PackagesDirectiveTypePythonPip,
		DefaultSpecFile: "requirements.txt",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s install --no-cache-dir -r %q", workdir, managerBin(files, "pip"), files.Spec)
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPoetry: {
		Type:            PackagesDirectiveTypePythonPoetry,
		DefaultSpecFile: "pyproject.toml",
		DefaultLockFile: "poetry.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s sync --no-root", workdir, managerBin(files, "poetry"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypeRustCargo: {
		Type:            PackagesDirectiveTypeRustCargo,
		DefaultSpecFile: "Cargo.toml",
		DefaultLockFile: "Cargo.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s fetch", workdir, managerBin(files, "cargo"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "rust-cargo-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptNpm: {
		Type:            PackagesDirectiveTypeJavaScriptNpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "package-lock.json",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s ci", workdir, managerBin(files, "npm"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptYarn: {
		Type:            PackagesDirectiveTypeJavaScriptYarn,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "yarn.lock",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s install --frozen-lockfile", workdir, managerBin(files, "yarn"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptPnpm: {
		Type:            PackagesDirectiveTypeJavaScriptPnpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "pnpm-lock.yaml",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s install --frozen-lockfile", workdir, managerBin(files, "pnpm"))
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeLuaRock: {
		Type:            PackagesDirectiveTypeLuaRock,
		DefaultSpecFile: "",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && %s install --only-deps %q", workdir, managerBin(files, "luarocks"), files.Spec)
			if prefix := formatEnvVars(env); prefix != "" {
				cmd = fmt.Sprintf("%s %s", prefix, cmd)
			}
			return cmd
		},
		CatalogerName: "lua-rock-cataloger",
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
