package config

import (
	"encoding/json"
	"fmt"
	"sort"
)

// SBOMBuildContextLabel names the private declaration an image carries about how its own
// composition is to be described. It never reaches a built image: the stage that writes
// the labels strips it, and only the recipe states it.
const SBOMBuildContextLabel = "werf.io/sbom-build-context-v1"

// bootstrapDeclared answers whether an image declares itself a bootstrap image: one built
// to be imported from and never shipped.
//
// Only this one field is read here, and a declaration that cannot be read at all is
// treated as declaring nothing: what the declaration as a whole must look like is settled
// where it is acted upon, by a decoder that refuses anything it does not know. This
// answers a question about the shape of the recipe, and a recipe whose declaration is
// malformed is refused there rather than quietly taken for a bootstrap one here.
func bootstrapDeclared(image ImageInterface) bool {
	stapel, isStapel := image.(StapelImageInterface)
	if !isStapel {
		return false
	}
	spec := stapel.ImageBaseConfig().ImageSpec
	if spec == nil {
		return false
	}
	raw, present := spec.Labels[SBOMBuildContextLabel]
	if !present {
		return false
	}
	var declaration struct {
		Bootstrap bool `json:"bootstrap"`
	}
	if err := json.Unmarshal([]byte(raw), &declaration); err != nil {
		return false
	}

	return declaration.Bootstrap
}

// validateBootstrapImages holds a bootstrap image to what being one means: it is built so
// that other images may take files out of it, and nothing else.
//
// Nothing of its own composition is described, so anything that would carry that
// composition into a described image - shipping it, standing underneath one as its base,
// or being named as a dependency of one - would put bytes nobody accounts for where this
// project claims to account for everything. An import is the one relation that does not:
// what it brings is named file by file and answered for by the image that imports it.
func (c *WerfConfig) validateBootstrapImages() error {
	if c.Meta.Build.Sbom == nil || !c.Meta.Build.Sbom.Enable {
		return nil
	}

	bootstrap := make(map[string]bool)
	for _, image := range c.Images(false) {
		if bootstrapDeclared(image) {
			bootstrap[image.GetName()] = true
		}
	}
	if len(bootstrap) == 0 {
		return nil
	}

	for _, image := range c.Images(false) {
		if bootstrap[image.GetName()] && image.IsFinal() {
			return newConfigError(fmt.Sprintf("image %q is declared a bootstrap image, so it cannot be final: a bootstrap image is built to be imported from and is never shipped", image.GetName()))
		}

		dependsOn := image.dependsOn()
		if bootstrap[dependsOn.From] {
			return newConfigError(fmt.Sprintf("image %q is built from %q, which is declared a bootstrap image: a bootstrap image can only be imported from", image.GetName(), dependsOn.From))
		}
		for _, name := range dependsOn.Dependencies {
			if bootstrap[name] {
				return newConfigError(fmt.Sprintf("image %q names %q as a dependency, which is declared a bootstrap image: a bootstrap image can only be imported from", image.GetName(), name))
			}
		}
	}

	names := make([]string, 0, len(bootstrap))
	for name := range bootstrap {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !c.importedFrom(name) {
			return newConfigError(fmt.Sprintf("image %q is declared a bootstrap image, but no image imports from it: a bootstrap image that nothing imports from is built for nothing", name))
		}
	}

	return nil
}

func (c *WerfConfig) importedFrom(name string) bool {
	for _, image := range c.Images(false) {
		for _, imported := range image.dependsOn().Imports {
			if imported == name {
				return true
			}
		}
	}

	return false
}
