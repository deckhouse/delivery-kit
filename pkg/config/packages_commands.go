package config

import "fmt"

const (
	ContainerFactoryVersionDir  = "/var/lib/pm"
	ContainerFactoryVersionFile = ContainerFactoryVersionDir + "/container-factory-version"

	// resolvePmEnvFromSecrets makes PACKAGES_VERSION and REGISTRY available as shell
	// environment variables when they are provided via werf build secrets, which are
	// mounted as files under /run/secrets/<id> instead of being exported into the shell.
	// If the variable is already set (e.g. via the base image ENV) it is kept as is.
	// The exported values persist for the rest of the packages stage script, so the
	// snapshot guard below and the subsequent `pm sync` invocation both see them.
	resolvePmEnvFromSecrets = `export PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}"; ` +
		`export REGISTRY="${REGISTRY:-$(cat /run/secrets/REGISTRY 2>/dev/null || true)}"`

	containerFactoryVersionSnapshotCmdTmpl = resolvePmEnvFromSecrets +
		`; : "${PACKAGES_VERSION:?required by werf for pm SBOM provenance}" && mkdir -p %s && printf '%%s\n' "$PACKAGES_VERSION" > %s`
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
