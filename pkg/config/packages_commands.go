package config

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/os_pm/metadata"
	"github.com/werf/werf/v3/pkg/stapel"
)

const packagesVersionEnvName = "PACKAGES_VERSION"

// Expanded by bash inside "${VAR:?...}", so the quotes of the example are escaped for that context.
const packagesVersionMissingMessage = `werf records it in the SBOM; set it in packages[].env, e.g. PACKAGES_VERSION: \"%secret:PACKAGES_VERSION%\"`

// The default stays unquoted so that an entry without `manager` keeps the command it had
// before the field existed, and with it the packages stage digest.
func managerBin(files FileBasedSpec, defaultBin string) string {
	if files.Manager == "" {
		return defaultBin
	}

	return fmt.Sprintf("%q", files.Manager)
}

// A value read from a secret gets a statement of its own instead of staying in the command
// prefix: bash does not apply `set -e` to a failed command substitution in a prefix, so an
// unreadable secret would otherwise let the package manager run with the variable empty.
// Every directive runs in the same stage script, so such a statement would overwrite a
// variable the base image exports for every later directive; the caller keeps it local
// by running the assignments together with the package manager in a subshell.
func formatEnvVars(env map[string]string, standalone []string) ([]string, string) {
	if len(env) == 0 {
		return nil, ""
	}

	keys := lo.Keys(env)
	sort.Strings(keys)

	var assignments, parts []string
	for _, key := range keys {
		assignment := fmt.Sprintf("%s=%s", key, formatPackageEnvValue(env[key]))

		if !lo.Contains(standalone, key) && !packageEnvValueReadsSecret(env[key]) {
			parts = append(parts, assignment)
			continue
		}

		assignments = append(assignments, assignment)
		parts = append(parts, fmt.Sprintf(`%s="$%s"`, key, key))
	}

	return assignments, strings.Join(parts, " ")
}

func joinDirective(assignments, commands []string) string {
	if len(assignments) == 0 {
		return strings.Join(commands, "; ")
	}

	return fmt.Sprintf("(%s)", strings.Join(append(assignments, commands...), "; "))
}

// `cd` stays in the parent shell: a later directive may use a relative workdir that
// counts on it, as it did when every command ran there.
func formatWorkdirCommand(workdir, command string, env map[string]string) string {
	assignments, prefix := formatEnvVars(env, nil)
	if prefix != "" {
		command = fmt.Sprintf("%s %s", prefix, command)
	}

	return fmt.Sprintf("cd %q && %s", workdir, joinDirective(assignments, []string{command}))
}

func formatMkdirCommand() string {
	return fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), path.Dir(metadata.ContainerFactoryVersionPath))
}

func formatVersionFileCommand() string {
	return fmt.Sprintf(
		`: "${%[1]s:?%[2]s}" && printf '%%s\n' "$%[1]s" > %[3]s`,
		packagesVersionEnvName, packagesVersionMissingMessage, metadata.ContainerFactoryVersionPath,
	)
}

func formatInstallCommand(pkgs []string, env map[string]string) string {
	assignments, prefix := formatEnvVars(env, []string{packagesVersionEnvName})

	commands := []string{
		formatMkdirCommand(),
		formatVersionFileCommand(),
		strings.TrimSpace(fmt.Sprintf("%s pm install %s", prefix, strings.Join(pkgs, " "))),
	}

	return joinDirective(assignments, commands)
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
