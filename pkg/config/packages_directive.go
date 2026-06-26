package config

import (
	"fmt"
	"sort"
)

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
		if len(d.Spec.Packages) == 0 {
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

// normalizePackages flattens all packages across every directive, deduplicates
// and sorts them, and returns a single directive with the normalized list.
// This is called during config conversion so that the build stage receives
// a ready-to-use package list without needing to re-resolve or deduplicate.
func normalizePackages(packages []*PackagesDirective) []*PackagesDirective {
	seen := map[string]bool{}
	var all []string

	for _, p := range packages {
		for _, name := range p.Spec.Packages {
			if !seen[name] {
				seen[name] = true
				all = append(all, name)
			}
		}
	}

	if len(all) == 0 {
		return nil
	}

	sort.Strings(all)

	return []*PackagesDirective{
		{
			Type: PackagesDirectiveTypeOSPM,
			Spec: PackagesSpec{Packages: all},
		},
	}
}
