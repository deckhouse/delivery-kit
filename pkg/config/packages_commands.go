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
	ContainerFactoryVersionDir  = "/var/lib/pm"
	ContainerFactoryVersionFile = ContainerFactoryVersionDir + "/container-factory-version"
)

func formatSecretVar(name string) string {
	// Read the secret with stapel `head`, which is scratch-safe (embedded in the stapel
	// toolchain, so it works on a base image without its own coreutils). The stapel
	// toolchain no longer embeds `cat`, and the bash `$(<file)` builtin cannot be used
	// here because the `2>/dev/null || true` guard turns it into a bare redirection that
	// yields an empty value.
	return fmt.Sprintf(
		`%[1]s="${%[1]s:-$(%[2]s /run/secrets/%[1]s 2>/dev/null || true)}"`,
		name, stapel.HeadBinPath(),
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

func formatSyncCommand(lockFile string, env map[string]string) string {
	var parts []string
	if envPrefix := formatEnvVars(env); envPrefix != "" {
		parts = append(parts, envPrefix)
	}
	parts = append(parts, formatSecretVar("PACKAGES_VERSION"), formatSecretVar("REGISTRY"), "pm sync --from", lockFile)
	return strings.Join(parts, " ")
}

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	for _, pkg := range packages {
		eco, ok := ecosystems[pkg.Type]
		if !ok {
			continue
		}

		commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased.Spec, pkg.FileBased.Lock, pkg.Env))
	}
	return commands
}
