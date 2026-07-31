package config

import (
	"fmt"
	"maps"
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
	Packages []string
}

type FileBasedSpec struct {
	Workdir string
	Spec    string
	Lock    string
}

type PackageEcosystem struct {
	Type            PackagesDirectiveType
	DefaultSpecFile string
	DefaultLockFile string
	InstallCmd      func(workdir, specFile string, specList []string, env map[string]string) string
	CatalogerName   string
}

var ecosystems = map[PackagesDirectiveType]PackageEcosystem{
	PackagesDirectiveTypeGoMod: {
		Type:            PackagesDirectiveTypeGoMod,
		DefaultSpecFile: "go.mod",
		DefaultLockFile: "go.sum",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && go mod download", workdir)
		},
		CatalogerName: "go-module-file-cataloger",
	},
	PackagesDirectiveTypePythonUV: {
		Type:            PackagesDirectiveTypePythonUV,
		DefaultSpecFile: "pyproject.toml",
		DefaultLockFile: "uv.lock",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && uv sync --frozen", workdir)
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPip: {
		Type:            PackagesDirectiveTypePythonPip,
		DefaultSpecFile: "requirements.txt",
		DefaultLockFile: "",
		InstallCmd: func(workdir, spec string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && pip install --no-cache-dir -r %q", workdir, spec)
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPoetry: {
		Type:            PackagesDirectiveTypePythonPoetry,
		DefaultSpecFile: "pyproject.toml",
		DefaultLockFile: "poetry.lock",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && poetry sync --no-root", workdir)
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypeRustCargo: {
		Type:            PackagesDirectiveTypeRustCargo,
		DefaultSpecFile: "Cargo.toml",
		DefaultLockFile: "Cargo.lock",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && cargo fetch", workdir)
		},
		CatalogerName: "rust-cargo-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptNpm: {
		Type:            PackagesDirectiveTypeJavaScriptNpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "package-lock.json",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && npm ci", workdir)
		},
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptYarn: {
		Type:            PackagesDirectiveTypeJavaScriptYarn,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "yarn.lock",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && yarn install --frozen-lockfile", workdir)
		},
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptPnpm: {
		Type:            PackagesDirectiveTypeJavaScriptPnpm,
		DefaultSpecFile: "package.json",
		DefaultLockFile: "pnpm-lock.yaml",
		InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && pnpm install --frozen-lockfile", workdir)
		},
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeLuaRock: {
		Type:            PackagesDirectiveTypeLuaRock,
		DefaultSpecFile: "",
		DefaultLockFile: "",
		InstallCmd: func(workdir, spec string, _ []string, _ map[string]string) string {
			return fmt.Sprintf("cd %q && luarocks install --only-deps %q", workdir, spec)
		},
		CatalogerName: "lua-rock-cataloger",
	},
	PackagesDirectiveTypeOSPM: {
		Type: PackagesDirectiveTypeOSPM,
		InstallCmd: func(_, _ string, specList []string, env map[string]string) string {
			return fmt.Sprintf("%s; %s; %s", formatMkdirCommand(), formatVersionFileCommand(), formatInstallCommand(specList, env))
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

func (d *PackagesDirective) validate() error {
	if _, ok := ecosystems[d.Type]; !ok {
		return fmt.Errorf("unsupported packages type %q", d.Type)
	}

	if d.Type == PackagesDirectiveTypeOSPM {
		if len(d.Spec.Packages) == 0 {
			return fmt.Errorf("packages spec must not be empty for type %q", d.Type)
		}
		return nil
	}

	if d.FileBased.Workdir == "" {
		return fmt.Errorf("the `workdir` is required for type %q", d.Type)
	}
	if d.FileBased.Spec == "" {
		return fmt.Errorf("the `spec` is required for type %q", d.Type)
	}
	return nil
}
