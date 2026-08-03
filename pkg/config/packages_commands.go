package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/stapel"
)

func formatEnvVars(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}

	keys := lo.Keys(env)
	sort.Strings(keys)

	parts := lo.Map(keys, func(k string, _ int) string {
		return fmt.Sprintf(`%s=%q`, k, env[k])
	})
	return strings.Join(parts, " ")
}

const (
	ContainerFactoryVersionDir       = "/var/lib/pm"
	ContainerFactoryVersionFile      = ContainerFactoryVersionDir + "/container-factory-version"
	ContainerFactoryVersionIndexFile = ContainerFactoryVersionDir + "/index.json"
)

func formatSecretVar(name string) string {
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
		formatSecretVar("PACKAGES_VERSION"), ContainerFactoryVersionFile,
	)
}

func formatInstallCommand(pkgs []string, env map[string]string) string {
	var parts []string
	if envPrefix := formatEnvVars(env); envPrefix != "" {
		parts = append(parts, envPrefix)
	}
	parts = append(parts, formatSecretVar("PACKAGES_VERSION"), formatSecretVar("REGISTRY"), "pm install", strings.Join(pkgs, " "))
	return strings.Join(parts, " ")
}

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	for _, pkg := range packages {
		eco, ok := ecosystems[pkg.Type]
		if !ok {
			continue
		}

		commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased.Spec, pkg.Spec.Packages, pkg.Env))
	}
	return commands
}
