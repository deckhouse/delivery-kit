package config

import "fmt"

// PackagesDirectiveType enumerates supported package source types.
type PackagesDirectiveType string

const (
	PackagesDirectiveTypeOSPM PackagesDirectiveType = "os-pm"
)

// PackagesSpec stores a package specification which is either a file path
// (string) or an inline package list ([]string).
type PackagesSpec struct {
	FilePath string
	Packages []string
}

// PackagesDirective represents a single entry in the image-level packages list.
type PackagesDirective struct {
	Type PackagesDirectiveType
	Spec PackagesSpec
}

func (d *PackagesDirective) validate() error {
	if d.Type != PackagesDirectiveTypeOSPM {
		return fmt.Errorf("unsupported packages type %q", d.Type)
	}

	if d.Spec.FilePath == "" && len(d.Spec.Packages) == 0 {
		return fmt.Errorf("packages spec must not be empty for type %q", d.Type)
	}

	return nil
}
