package config

type PackagesCommandsOptions struct {
	DeclaredSecretIDs map[string]struct{}
}

func GeneratePackagesCommands(packages []*PackagesDirective, options PackagesCommandsOptions) []string {
	var commands []string
	for _, pkg := range packages {
		eco, ok := ecosystems[pkg.Type]
		if !ok {
			continue
		}

		commands = append(commands, eco.InstallCmd(pkg.FileBased.Workdir, pkg.FileBased, pkg.Spec.Packages, pkg.Env, options))
	}
	return commands
}
