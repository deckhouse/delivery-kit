package convergefailure

// ImportSource is an image an image imports from. Only in-project imports take
// part in SBOM failure semantics: an external image is not produced by this run,
// so its missing SBOM is a property of a foreign artifact, not a failure here.
type ImportSource struct {
	ImageName string
	External  bool
}

// ImageDependencies describes the images whose SBOMs are merged into an image's
// own SBOM. A multi-platform image contributes one entry per platform.
type ImageDependencies struct {
	BaseImageName string
	Imports       []ImportSource
}

// DependencyImageNames collects the in-project image names an image's SBOM
// depends on. A failed or skipped dependency from this list makes the image's own
// SBOM ungenerable, which is what makes base images and import sources one kind
// for failure purposes.
func DependencyImageNames(deps []ImageDependencies) []string {
	var names []string
	for _, dep := range deps {
		if dep.BaseImageName != "" {
			names = append(names, dep.BaseImageName)
		}
		for _, importSource := range dep.Imports {
			if !importSource.External {
				names = append(names, importSource.ImageName)
			}
		}
	}
	return names
}
