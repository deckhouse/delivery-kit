package config

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"al.essio.dev/pkg/shellescape"
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
func formatWorkdirCommand(files FileBasedSpec, command string, env map[string]string) string {
	return formatWorkdirCommands(files, []string{command}, env)
}

// The environment prefix goes on the last command, the one that installs: a prefix
// applies to the simple command it precedes and nothing else.
//
// The lock is checked here rather than left to the manager: poetry, go, cargo and yarn 1
// resolve from the network and write a lock of their own when none is committed, so the
// stage would record an unpinned resolution in the SBOM without a word.
func formatWorkdirCommands(files FileBasedSpec, commands []string, env map[string]string) string {
	assignments, prefix := formatEnvVars(env, nil)
	commands = slices.Clone(commands)
	if prefix != "" {
		last := len(commands) - 1
		commands[last] = fmt.Sprintf("%s %s", prefix, commands[last])
	}

	steps := []string{fmt.Sprintf("cd %q", files.Workdir)}
	if files.Lock != "" {
		steps = append(steps, formatLockGuard(files))
	}
	steps = append(steps, joinDirective(assignments, []string{strings.Join(commands, " && ")}))

	return strings.Join(steps, " && ")
}

func formatLockGuard(files FileBasedSpec) string {
	return fmt.Sprintf(
		`{ test -f %q || { echo %s >&2; exit 1; }; }`,
		files.Lock,
		shellescape.Quote(fmt.Sprintf("lock file %s not found in %s; the packages stage installs only what the lock pins, commit it", files.Lock, files.Workdir)),
	)
}

func withDefaultEnv(env, defaults map[string]string) map[string]string {
	merged := maps.Clone(defaults)
	maps.Copy(merged, env)

	return merged
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

		commands = append(commands, eco.InstallCmd(pkg.FileBased, pkg.Spec.Packages, pkg.Env))
	}
	return commands
}
