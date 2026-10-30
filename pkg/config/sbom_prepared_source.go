package config

import (
	"encoding/json"
	"fmt"
)

// preparedSourceDeclared answers whether an image declares itself a prepared source: an
// image that is nothing but the files other images already answer for, collected so that
// builds downstream can consume it as the package it declares itself to be.
//
// Only this one field is read here, for the same reason bootstrapDeclared reads only its
// own: what the declaration as a whole must look like is settled where it is acted upon.
func preparedSourceDeclared(image ImageInterface) bool {
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
		PreparedSource bool `json:"preparedSource"`
	}
	if err := json.Unmarshal([]byte(raw), &declaration); err != nil {
		return false
	}

	return declaration.PreparedSource
}

// validatePreparedSourceImages holds a prepared source image to what being one means: it
// ships files this project already accounts for, and makes nothing of its own.
//
// It is the one image allowed to take files out of a bootstrap image without answering for
// them file by file, and that permission rests entirely on it producing nothing: it stands
// on no base, runs no command, adds nothing from a repository, installs no package. Every
// byte it ships was put there by an import from an image of this project, and the image is
// then itself what a pinned package consists of. Anything that could produce a byte here -
// a base image underneath it, a shell command, a git mapping, a packages directive - would
// make it an image whose composition is partly its own, which is exactly what it may not be.
func (c *WerfConfig) validatePreparedSourceImages() error {
	if c.Meta.Build.Sbom == nil || !c.Meta.Build.Sbom.Enable {
		return nil
	}

	prepared := make(map[string]bool)
	for _, image := range c.Images(false) {
		if preparedSourceDeclared(image) {
			prepared[image.GetName()] = true
		}
	}
	if len(prepared) == 0 {
		return nil
	}

	for _, image := range c.Images(false) {
		if !prepared[image.GetName()] {
			continue
		}
		if err := validatePreparedSourceImage(c, image); err != nil {
			return err
		}
	}

	return nil
}

func validatePreparedSourceImage(config *WerfConfig, image ImageInterface) error {
	name := image.GetName()
	if bootstrapDeclared(image) {
		return newConfigError(fmt.Sprintf("image %q is declared both a prepared source and a bootstrap image: an image either describes nothing of itself or is itself what a description names", name))
	}
	// Only a Stapel image can carry the declaration at all, which is what selected this
	// one.
	base := image.(StapelImageInterface).ImageBaseConfig()
	if base.From != "scratch" {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it is built from scratch: %q underneath it would ship bytes this image does not collect itself", name, base.From))
	}
	// Read before the commands: a packages directive is spelled out as commands of the
	// packages stage, and naming it for what it is says more than what it compiles to.
	if len(base.Packages) > 0 {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it installs no packages: a prepared source is itself what a package consists of", name))
	}
	if len(base.Mount) > 0 {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it mounts nothing: what a mount brings in is not among the files any import of this image placed here", name))
	}
	if len(base.Secrets) > 0 {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it takes no secrets: a prepared source is published and consumed as the package it is", name))
	}
	if len(base.Dependencies) > 0 {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it declares no dependencies: nothing here reads what another image was built as", name))
	}
	// A prepared source is consumed by pinning the package it is, not by shipping it:
	// a final image is one this project delivers, and this one is a source for others.
	// Images are final unless they say otherwise, so such a recipe has to say so.
	if image.IsFinal() {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it states final: false: it is consumed as the package it is, by the builds that pin it", name))
	}
	if base.Shell != nil && len(base.Shell.BeforeInstall)+len(base.Shell.Install)+len(base.Shell.BeforeSetup)+len(base.Shell.Setup)+len(base.Shell.Packages) > 0 {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it runs no commands: a prepared source collects files other images answer for and makes nothing of its own", name))
	}
	if base.Git != nil && len(base.Git.Local)+len(base.Git.Remote) > 0 {
		return newConfigError(fmt.Sprintf("image %q is declared a prepared source, so it adds nothing from a repository: every file it ships is imported from an image of this project", name))
	}
	for _, imported := range base.Import {
		// An image of this project is either a declared bootstrap image or one this
		// very build verifies. Whether the import was already resolved as external
		// depends on what ran before this check, so the recipe is asked directly.
		if config.GetImage(imported.From) == nil {
			return newConfigError(fmt.Sprintf("image %q is declared a prepared source and imports from %q, which is not an image of this project: what it would bring in is nobody's statement here", name, imported.From))
		}
	}

	return nil
}
