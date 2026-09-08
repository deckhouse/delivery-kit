package config

import (
	"fmt"
	"maps"
	"regexp"

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
	Version string
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
		InstallCmd: func(workdir string, _ FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && go mod download", workdir)
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
		InstallCmd:      newPackageCommandWrapper(PackagesDirectiveTypePythonUV, `sync --frozen`).InstallCmd,
		CatalogerName:   "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPip: {
		Type:            PackagesDirectiveTypePythonPip,
		DefaultSpecFile: "requirements.txt",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && pip install --no-cache-dir -r %q", workdir, files.Spec)
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
		InstallCmd:      newPackageCommandWrapper(PackagesDirectiveTypePythonPoetry, `sync --no-root`).InstallCmd,
		CatalogerName:   "python-package-cataloger",
	},
	PackagesDirectiveTypeRustCargo: {
		Type:            PackagesDirectiveTypeRustCargo,
		DefaultSpecFile: "Cargo.toml",
		DefaultLockFile: "Cargo.lock",
		InstallCmd: func(workdir string, _ FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && cargo fetch", workdir)
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
		InstallCmd: func(workdir string, _ FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && npm ci", workdir)
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
		InstallCmd:      newPackageCommandWrapper(PackagesDirectiveTypeJavaScriptYarn, `install --frozen-lockfile`).InstallCmd,
		CatalogerName:   "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptPnpm: {
		Type:            PackagesDirectiveTypeJavaScriptPnpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "pnpm-lock.yaml",
		InstallCmd:      newPackageCommandWrapper(PackagesDirectiveTypeJavaScriptPnpm, `install --frozen-lockfile`).InstallCmd,
		CatalogerName:   "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeLuaRock: {
		Type:            PackagesDirectiveTypeLuaRock,
		DefaultSpecFile: "",
		DefaultLockFile: "",
		InstallCmd: func(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
			cmd := fmt.Sprintf("cd %q && luarocks install --only-deps %q", workdir, files.Spec)
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

var exactManagerVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type packageCommandWrapper struct {
	typeName      PackagesDirectiveType
	installFormat string
}

func newPackageCommandWrapper(typeName PackagesDirectiveType, installFormat string) packageCommandWrapper {
	return packageCommandWrapper{typeName: typeName, installFormat: installFormat}
}

func (w packageCommandWrapper) InstallCmd(workdir string, files FileBasedSpec, _ []string, env map[string]string) string {
	lifecycle := alternativeManagerCommands(w.typeName, files, workdir, w.installFormat)
	return prefixCommand(lifecycle, env)
}

func prefixCommand(cmd string, env map[string]string) string {
	if prefix := formatEnvVars(env); prefix != "" {
		return fmt.Sprintf("%s %s", prefix, cmd)
	}
	return cmd
}

func isAlternativeManager(typeName PackagesDirectiveType) bool {
	switch typeName {
	case PackagesDirectiveTypeJavaScriptYarn, PackagesDirectiveTypeJavaScriptPnpm, PackagesDirectiveTypePythonUV, PackagesDirectiveTypePythonPoetry:
		return true
	default:
		return false
	}
}

const (
	javascriptAlternativeManagerTemplate = `
	if command -v %[1]s >/dev/null 2>&1; then
	  echo '%[1]s must not be pre-installed' >&2
	  exit 1
	else
	  set -e
	  scope=$(mktemp -d)
	  npm install --prefix "$scope" --no-save --package-lock=false %[1]s@%[2]s
	  "$scope/node_modules/.bin/%[1]s" --version | grep -Fx %[2]q
	  cd %[3]q
	  "$scope/node_modules/.bin/%[1]s" %[4]s
	  rm -rf "$scope"
	fi
	`
	pythonAlternativeManagerTemplate = `
	if command -v %[1]s >/dev/null 2>&1; then
	  echo '%[1]s must not be pre-installed' >&2
	  exit 1
	else
	  set -e
	  scope=$(mktemp -d)
	  python3 -m venv "$scope"
	  "$scope/bin/python" -m pip install --no-cache-dir %[1]s==%[2]s
	  "$scope/bin/%[1]s" --version | grep -F %[2]q
	  cd %[3]q
	  "$scope/bin/%[1]s" %[4]s
	  rm -rf "$scope"
	fi
	`
)

func alternativeManagerCommands(typeName PackagesDirectiveType, files FileBasedSpec, workdir, installArgs string) string {
	manager := alternativeManagerName(typeName)
	switch typeName {
	case PackagesDirectiveTypeJavaScriptYarn, PackagesDirectiveTypeJavaScriptPnpm:
		return fmt.Sprintf(javascriptAlternativeManagerTemplate, manager, files.Version, workdir, installArgs)
	case PackagesDirectiveTypePythonUV, PackagesDirectiveTypePythonPoetry:
		return fmt.Sprintf(pythonAlternativeManagerTemplate, manager, files.Version, workdir, installArgs)
	default:
		panic(fmt.Sprintf("unsupported alternative manager type %q", typeName))
	}
}

func alternativeManagerName(typeName PackagesDirectiveType) string {
	switch typeName {
	case PackagesDirectiveTypeJavaScriptYarn:
		return "yarn"
	case PackagesDirectiveTypeJavaScriptPnpm:
		return "pnpm"
	case PackagesDirectiveTypePythonUV:
		return "uv"
	case PackagesDirectiveTypePythonPoetry:
		return "poetry"
	default:
		panic(fmt.Sprintf("unsupported alternative manager type %q", typeName))
	}
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

	if isAlternativeManager(d.Type) {
		if d.FileBased.Version == "" {
			return fmt.Errorf("the `version` is required for type %q", d.Type)
		}
		if !exactManagerVersionPattern.MatchString(d.FileBased.Version) {
			return fmt.Errorf("the `version` must be an exact X.Y.Z version for type %q", d.Type)
		}
	} else if d.FileBased.Version != "" {
		return fmt.Errorf("the `version` is not supported for type %q", d.Type)
	}

	return nil
}
