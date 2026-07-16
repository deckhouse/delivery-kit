package config

import (
	"fmt"
	"maps"
	"path"
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

type FileBasedSpec struct {
	Workdir string
	Spec    string
	Lock    string
}

type PackageEcosystem struct {
	Type          PackagesDirectiveType
	DefaultSpec   string
	DefaultLock   string
	InstallCmd    func(workdir, spec string) string
	CatalogerName string
}

var ecosystems = map[PackagesDirectiveType]PackageEcosystem{
	PackagesDirectiveTypeGoMod: {
		Type:          PackagesDirectiveTypeGoMod,
		DefaultSpec:   "go.mod",
		DefaultLock:   "go.sum",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && go mod download", workdir) },
		CatalogerName: "go-module-file-cataloger",
	},
	PackagesDirectiveTypePythonUV: {
		Type:          PackagesDirectiveTypePythonUV,
		DefaultSpec:   "pyproject.toml",
		DefaultLock:   "uv.lock",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && uv sync --frozen", workdir) },
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPip: {
		Type:        PackagesDirectiveTypePythonPip,
		DefaultSpec: "requirements.txt",
		DefaultLock: "",
		InstallCmd: func(workdir, spec string) string {
			return fmt.Sprintf("cd %q && pip install --no-cache-dir -r %q", workdir, spec)
		},
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypePythonPoetry: {
		Type:          PackagesDirectiveTypePythonPoetry,
		DefaultSpec:   "pyproject.toml",
		DefaultLock:   "poetry.lock",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && poetry sync --no-root", workdir) },
		CatalogerName: "python-package-cataloger",
	},
	PackagesDirectiveTypeRustCargo: {
		Type:          PackagesDirectiveTypeRustCargo,
		DefaultSpec:   "Cargo.toml",
		DefaultLock:   "Cargo.lock",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && cargo fetch", workdir) },
		CatalogerName: "rust-cargo-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptNpm: {
		Type:          PackagesDirectiveTypeJavaScriptNpm,
		DefaultSpec:   "package.json",
		DefaultLock:   "package-lock.json",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && npm ci", workdir) },
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptYarn: {
		Type:          PackagesDirectiveTypeJavaScriptYarn,
		DefaultSpec:   "package.json",
		DefaultLock:   "yarn.lock",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && yarn install --frozen-lockfile", workdir) },
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeJavaScriptPnpm: {
		Type:          PackagesDirectiveTypeJavaScriptPnpm,
		DefaultSpec:   "package.json",
		DefaultLock:   "pnpm-lock.yaml",
		InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && pnpm install --frozen-lockfile", workdir) },
		CatalogerName: "javascript-lock-cataloger",
	},
	PackagesDirectiveTypeLuaRock: {
		Type:        PackagesDirectiveTypeLuaRock,
		DefaultSpec: "",
		DefaultLock: "",
		InstallCmd: func(workdir, spec string) string {
			return fmt.Sprintf("cd %q && luarocks install --only-deps %q", workdir, spec)
		},
		CatalogerName: "lua-rock-cataloger",
	},
	PackagesDirectiveTypeOSPM: {
		Type:        PackagesDirectiveTypeOSPM,
		DefaultSpec: "pm.yaml",
		DefaultLock: "pm.lock",
		InstallCmd:  func(workdir, _ string) string { return fmt.Sprintf("pm sync --from %s", path.Join(workdir, "pm.lock")) },
	},
}

// Ecosystems returns a defensive copy of the file-based package ecosystems registry.
// The returned map is safe to iterate; mutating it does not affect the internal registry.
func Ecosystems() map[PackagesDirectiveType]PackageEcosystem {
	return maps.Clone(ecosystems)
}

type PackagesDirective struct {
	Type      PackagesDirectiveType
	FileBased FileBasedSpec
}

func (d *PackagesDirective) validate() error {
	if _, ok := ecosystems[d.Type]; !ok {
		return fmt.Errorf("unsupported packages type %q", d.Type)
	}
	if d.FileBased.Workdir == "" {
		return fmt.Errorf("the `workdir` is required for type %q", d.Type)
	}
	if d.FileBased.Spec == "" {
		return fmt.Errorf("the `spec` is required for type %q", d.Type)
	}
	return nil
}
