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

func formatSecretVar(name string) string {
	// Bash reads the secret on its own: $(<file) is a redirection, and the [ -r ] guard keeps a
	// missing secret quiet. Suppressing the error with 2>/dev/null instead would turn $(<file)
	// into a bare redirection that yields nothing, and any external reader ties the stage to a
	// binary of the stapel image or the base.
	return fmt.Sprintf(
		`%[1]s="${%[1]s:-$([ -r /run/secrets/%[1]s ] && printf '%%s' "$(</run/secrets/%[1]s)" || true)}"`,
		name,
	)
}

func formatMkdirCommand() string {
	return fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), path.Dir(metadata.ContainerFactoryVersionPath))
}

func formatVersionFileCommand() string {
	return fmt.Sprintf(
		`%s && : "${PACKAGES_VERSION:?required by werf for pm SBOM provenance}" && printf '%%s\n' "$PACKAGES_VERSION" > %s`,
		formatSecretVar("PACKAGES_VERSION"), metadata.ContainerFactoryVersionPath,
	)
}

func formatInstallCommand(pkgs []string, env map[string]string) string {
	commandPrefix := []string{formatMkdirCommand(), formatVersionFileCommand()}
	envPrefix := strings.TrimSpace(strings.Join([]string{
		formatEnvVars(env),
		formatSecretVar("PACKAGES_VERSION"),
		formatSecretVar("REGISTRY"),
	}, " "))
	installCommand := fmt.Sprintf("%s pm install %s", envPrefix, strings.Join(pkgs, " "))

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
