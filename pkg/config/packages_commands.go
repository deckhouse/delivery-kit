package config

import "fmt"

const (
	ContainerFactoryVersionDir  = "/var/lib/pm"
	ContainerFactoryVersionFile = ContainerFactoryVersionDir + "/container-factory-version"

	containerFactoryVersionSnapshotCmdTmpl = `: "${PACKAGES_VERSION:?required by werf for pm SBOM provenance}" && mkdir -p %s && printf '%%s\n' "$PACKAGES_VERSION" > %s`
)

func ContainerFactoryVersionSnapshotCmd() string {
	return fmt.Sprintf(containerFactoryVersionSnapshotCmdTmpl, ContainerFactoryVersionDir, ContainerFactoryVersionFile)
}

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	snapshotted := false
	for _, pkg := range packages {
		eco, ok := ecosystems[pkg.Type]
		if !ok {
			continue
		}
		if pkg.Type == PackagesDirectiveTypeOSPM && !snapshotted {
			commands = append(commands, ContainerFactoryVersionSnapshotCmd())
			snapshotted = true
		}
		commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased.Spec))
	}
	return commands
}
