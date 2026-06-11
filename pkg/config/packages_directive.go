package config

import "fmt"

type PackagesDirectiveType string

const (
	PackagesDirectiveTypeOSPM  PackagesDirectiveType = "os-pm"
	PackagesDirectiveTypeGoMod PackagesDirectiveType = "go-mod"
)

const (
	goModDefaultSpec = "go.mod"
	goModDefaultLock = "go.sum"
)

type PackagesSpec struct {
	FilePath string
	Packages []string
}

// GoModSpec describes Go module files inside the image. Workdir is the directory
// holding the module files; Spec and Lock default to "go.mod" and "go.sum".
type GoModSpec struct {
	Workdir string
	Spec    string
	Lock    string
}

type PackagesDirective struct {
	Type  PackagesDirectiveType
	Spec  PackagesSpec
	GoMod GoModSpec
}

func (d *PackagesDirective) validate() error {
	switch d.Type {
	case PackagesDirectiveTypeOSPM:
		if d.Spec.FilePath == "" && len(d.Spec.Packages) == 0 {
			return fmt.Errorf("packages spec must not be empty for type %q", d.Type)
		}
	case PackagesDirectiveTypeGoMod:
		if d.GoMod.Workdir == "" {
			return fmt.Errorf("the `workdir` is required for type %q", d.Type)
		}
	default:
		return fmt.Errorf("unsupported packages type %q", d.Type)
	}

	return nil
}
