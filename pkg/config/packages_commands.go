package config

import "fmt"

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	for _, pkg := range packages {
		switch pkg.Type {
		case PackagesDirectiveTypeOSPM:
			for _, p := range pkg.Spec.Packages {
				commands = append(commands, fmt.Sprintf("pm install %s", p))
			}
		case PackagesDirectiveTypeGoMod:
			commands = append(commands, fmt.Sprintf("cd %s && go mod download", pkg.GoMod.Workdir))
		}
	}
	return commands
}
