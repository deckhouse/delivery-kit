package config

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/os_pm/metadata"
	"github.com/werf/werf/v2/pkg/stapel"
)

// The default stays unquoted so that an entry without `manager` keeps the command it had
// before the field existed, and with it the packages stage digest.
func managerBin(files FileBasedSpec, defaultBin string) string {
	if files.Manager == "" {
		return defaultBin
	}

	return fmt.Sprintf("%q", files.Manager)
}

func formatEnvVars(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}

	keys := lo.Keys(env)
	sort.Strings(keys)

	parts := lo.Map(keys, func(k string, _ int) string {
		return fmt.Sprintf("%s=%s", k, formatPackageEnvValue(env[k]))
	})
	return strings.Join(parts, " ")
}

func formatWorkdirCommand(workdir, command string, env map[string]string) string {
	if prefix := formatEnvVars(env); prefix != "" {
		command = fmt.Sprintf("%s %s", prefix, command)
	}
	return fmt.Sprintf("cd %q && %s", workdir, command)
}

func formatMkdirCommand() string {
	return fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), path.Dir(metadata.ContainerFactoryVersionPath))
}

func formatVersionFileCommand(env map[string]string) string {
	guard := fmt.Sprintf(
		`: "${PACKAGES_VERSION:?required by werf for pm SBOM provenance}" && printf '%%s\n' "$PACKAGES_VERSION" > %s`,
		metadata.ContainerFactoryVersionPath,
	)

	value, ok := env["PACKAGES_VERSION"]
	if !ok {
		return guard
	}

	return fmt.Sprintf("PACKAGES_VERSION=%s && %s", formatPackageEnvValue(value), guard)
}

func formatInstallCommand(pkgs []string, env map[string]string) string {
	commandPrefix := []string{formatMkdirCommand(), formatVersionFileCommand(env)}
	installCommand := strings.TrimSpace(fmt.Sprintf("%s pm install %s", formatEnvVars(env), strings.Join(pkgs, " ")))

	return strings.Join(append(commandPrefix, installCommand), "; ")
}

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	for _, pkg := range packages {
		eco, ok := ecosystems[pkg.Type]
		if !ok {
			continue
		}

		commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased, pkg.Spec.Packages, pkg.Env))
	}
	return commands
}
