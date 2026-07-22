package config

import (
	"fmt"
	"strings"

	"github.com/werf/werf/v2/pkg/stapel"
)

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

		commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased.Spec, pkg.Spec.Packages))
	}
	return commands
}
