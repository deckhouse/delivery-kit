package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/werf/werf/v2/pkg/stapel"
)

func formatEnvVars(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s=%q`, k, env[k]))
	}
	return strings.Join(parts, " ")
}

const (
	ContainerFactoryVersionDir       = "/var/lib/pm"
	ContainerFactoryVersionFile      = ContainerFactoryVersionDir + "/container-factory-version"
	ContainerFactoryVersionIndexFile = ContainerFactoryVersionDir + "/index.json"
)

func envVarTmpl(name string) string {
	return fmt.Sprintf(
		`%[1]s="${%[1]s:-$(%[2]s /run/secrets/%[1]s 2>/dev/null || true)}"`,
		name, stapel.CatBinPath(),
	)
}

func formatMkdirCommand() string {
	return fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), ContainerFactoryVersionDir)
}

func formatVersionFileCommand() string {
	return fmt.Sprintf(
		`%s && : "${PACKAGES_VERSION:?required by werf for pm SBOM provenance}" && printf '%%s\n' "$PACKAGES_VERSION" > %s`,
		envVarTmpl("PACKAGES_VERSION"), ContainerFactoryVersionFile,
	)
}

func formatInstallCommand(pkgs []string) string {
	return fmt.Sprintf("%s %s pm install %s", envVarTmpl("PACKAGES_VERSION"), envVarTmpl("REGISTRY"), strings.Join(pkgs, " "))
}

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	for _, pkg := range packages {
		eco, ok := ecosystems[pkg.Type]
		if !ok {
			continue
		}

		cmd := eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased.Spec, pkg.Spec.Packages)

		if pkg.Type == PackagesDirectiveTypeOSPM && len(pkg.Env) > 0 {
			envPrefix := formatEnvVars(pkg.Env)
			cmd = strings.Replace(cmd, "pm install", envPrefix+" pm install", 1)
		}

		commands = append(commands, cmd)
	}
	return commands
}
