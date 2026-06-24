package config

import "fmt"

func GeneratePackagesCommands(packages []*PackagesDirective) []string {
	var commands []string
	for _, pkg := range packages {
		if pkg.Type == PackagesDirectiveTypeGoMod {
			commands = append(commands, fmt.Sprintf("cd %s && go mod download", pkg.GoMod.Workdir))
		}
	}
	return commands
}
