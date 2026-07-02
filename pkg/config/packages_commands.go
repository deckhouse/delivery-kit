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
		if pkg.Type == PackagesDirectiveTypeOSPM {
			if len(pkg.Spec.Packages) == 0 {
				continue
			}
			if !snapshotted {
				commands = append(commands, ContainerFactoryVersionSnapshotCmd())
				snapshotted = true
			}
			for _, p := range pkg.Spec.Packages {
				commands = append(commands, fmt.Sprintf("pm install %s", p))
			}
			continue
		}
		if eco, ok := ecosystems[pkg.Type]; ok {
			commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased.Spec))
		}
	}
	return commands
}
