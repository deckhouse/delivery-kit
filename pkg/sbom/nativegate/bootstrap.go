package nativegate

import (
	"context"
	"fmt"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func validateBootstrapInputs(ctx context.Context, img v1.Image, packages *PackageSet, platform string) error {
	if !slices.ContainsFunc(packages.Originals, func(original Original) bool { return original.Kind == "bootstrap" }) {
		return nil
	}
	fs, err := readFilesystem(ctx, img)
	if err != nil {
		return err
	}
	trusted := map[string]bool{}
	catalog := Catalog{Components: map[string]cdx.Component{}}
	for _, component := range packages.Components {
		catalog.Components[component.BOMRef] = component
		if source, ok := componentSource(component); ok {
			trusted[sourceIdentity(source)] = true
		}
	}
	ins := inspector{policy: strictPolicy(platform), catalog: &catalog}
	for _, original := range packages.Originals {
		if original.Kind != "bootstrap" || servicePath(original.Path) {
			continue
		}
		filename, err := resolveRegularOriginal(fs, original.Path)
		if err != nil {
			return err
		}
		file, exists := fs.index.Files[filename]
		if !exists {
			continue
		}
		if file.Digest != original.SHA256 {
			return fmt.Errorf("%s: hash-mismatch: bootstrap import changed", filename)
		}
		known := false
		for _, candidate := range packages.Originals {
			if candidate.Kind == "bootstrap" || candidate.SHA256 != file.Digest {
				continue
			}
			resolved, err := resolveRegularOriginal(fs, candidate.Path)
			if err != nil {
				return err
			}
			if resolved == filename {
				known = true
				break
			}
		}
		if known {
			continue
		}
		matched, err := matchPackageOriginal(filename, file.Digest, packages.Originals)
		if err != nil {
			return err
		}
		if matched != nil {
			continue
		}
		record, native, err := ins.inspect(fs.bodies[filename])
		if err != nil {
			return fmt.Errorf("%s: bootstrap input: %w", filename, err)
		}
		if !native {
			return fmt.Errorf("%s: no-data: bootstrap input has neither a build record nor a trusted original", filename)
		}
		for _, ref := range record.Components {
			source, ok := componentSource(catalog.Components[ref])
			if !ok || (source.Kind == "pm" && !trusted[sourceIdentity(source)]) {
				return fmt.Errorf("%s: bootstrap input has unknown package %s", filename, catalog.Components[ref].Name)
			}
		}
	}
	return nil
}
