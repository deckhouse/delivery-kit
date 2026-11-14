package nativegate

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	verificationProperty = "dk:verification"
	verifiedImage        = "instrumented-v1"
)

func Verify(ctx context.Context, img v1.Image, target *cdx.BOM, opts VerifyOptions) error {
	if opts.Platform != "linux/amd64" && opts.Platform != "linux/arm64" {
		return fmt.Errorf("unsupported platform %s", opts.Platform)
	}
	if opts.Subject == "" {
		return fmt.Errorf("no-data: missing image subject")
	}
	for _, root := range opts.UserRoots {
		if !path.IsAbs(root) || path.Clean(root) != root || root == "/" {
			return fmt.Errorf("invalid user source root %q", root)
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("read image platform: %w", err)
	}
	if cfg.OS+"/"+cfg.Architecture != opts.Platform {
		return fmt.Errorf("image platform %s/%s differs from %s", cfg.OS, cfg.Architecture, opts.Platform)
	}
	fs, err := readFilesystem(ctx, img, ImagePolicy{Role: "final"})
	if err != nil {
		return fmt.Errorf("read image filesystem: %w", err)
	}
	originals := make(map[string]Original)
	trusted := make(map[string]bool)
	for _, component := range opts.TrustedComponents {
		if source, ok := componentSource(component); ok {
			trusted[sourceIdentity(source)] = true
		}
	}
	for _, original := range opts.Originals {
		if !digestPattern.MatchString(original.SHA256) || original.Component.BOMRef == "" || original.Component.Name == "" {
			return fmt.Errorf("%s: no-data: incomplete original %s", original.Path, original.Kind)
		}
		if original.Kind == "pm" {
			source, ok := componentSource(original.Component)
			if !ok || source.Kind != "pm" || source.Locator == "" || !digestPattern.MatchString(source.Checksum) {
				return fmt.Errorf("%s: no-data: package has no instrumented source", original.Path)
			}
			trusted[sourceIdentity(source)] = true
		}
		resolved, err := resolvePath(fs, original.Path)
		if err != nil {
			return err
		}
		if previous, exists := originals[resolved]; exists && (previous.SHA256 != original.SHA256 || previous.Component.BOMRef != original.Component.BOMRef) {
			return fmt.Errorf("%s: ambiguous original ownership", resolved)
		}
		originals[resolved] = original
	}
	policy := &Policy{Platform: opts.Platform, Profiles: []string{"c-object", "c-relocatable", "c-static", "c-dynamic", "go", "go-cgo-static", "go-cgo-dynamic"}}
	catalog := Catalog{Components: make(map[string]cdx.Component)}
	present := make(map[string]Record)
	for _, name := range slices.Sorted(maps.Keys(fs.index.Files)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		file := fs.index.Files[name]
		original, known := originals[name]
		if known && file.Digest != original.SHA256 {
			return fmt.Errorf("%s: hash-mismatch: %s original changed", name, original.Kind)
		}
		ins := inspector{policy: policy, catalog: &catalog}
		record, native, err := ins.inspect(fs.bodies[name])
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if native {
			for _, ref := range record.Components {
				source, ok := componentSource(catalog.Components[ref])
				if !ok {
					return fmt.Errorf("%s: no-data: component %s has no source", name, ref)
				}
				if source.Kind == "pm" && !trusted[sourceIdentity(source)] {
					return fmt.Errorf("%s: no-data: unknown package %s", name, catalog.Components[ref].Name)
				}
			}
		} else if file.Size > 0 && binaryLike(fs.bodies[name], fs.executable[name], name) && !interpretedScript(fs.bodies[name], name) && !plainText(fs.bodies[name], name) {
			return fmt.Errorf("%s: unsupported binary format", name)
		}
		record.Path, record.SHA256 = name, file.Digest
		switch {
		case known:
			catalog.Components[original.Component.BOMRef] = original.Component
			record.Components = appendUnique(record.Components, original.Component.BOMRef)
			record.Owners = []string{original.Component.BOMRef}
			record.Origin = original.Kind
		case native:
			record.Origin = "build"
		case userFile(name, opts.UserRoots):
			ref := "urn:dk:generated:" + opts.Subject
			catalog.Components[ref] = cdx.Component{Type: cdx.ComponentTypeApplication, BOMRef: ref, Name: opts.Subject, Properties: &[]cdx.Property{{Name: verificationProperty, Value: "generated"}}}
			record.Components, record.Origin = []string{ref}, "generated"
		case pmStateFile(name):
			continue
		default:
			return fmt.Errorf("%s: no-data: file has no trusted original; directory is not in a git mapping/WorkingDir", name)
		}
		present[name] = record
	}
	for _, env := range cfg.Config.Env {
		key, value, _ := strings.Cut(env, "=")
		if value != "" && slices.Contains([]string{"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"}, key) {
			return fmt.Errorf("unsupported dynamic loader environment %s", key)
		}
	}
	edges, _, err := runtimeDependencies(fs, present, false)
	if err != nil {
		return err
	}
	if err := catalog.writeBOM(present, edges, target); err != nil {
		return err
	}
	if target.Metadata == nil {
		target.Metadata = &cdx.Metadata{}
	}
	properties := []cdx.Property{}
	if target.Metadata.Properties != nil {
		properties = *target.Metadata.Properties
	}
	properties = append(properties, cdx.Property{Name: verificationProperty, Value: verifiedImage}, cdx.Property{Name: "dk:platform", Value: opts.Platform})
	target.Metadata.Properties = &properties
	return nil
}

func userFile(name string, roots []string) bool {
	return slices.ContainsFunc(roots, func(root string) bool { return name == root || strings.HasPrefix(name, root+"/") })
}

func pmStateFile(name string) bool {
	return slices.Contains([]string{"/var/lib/pm/index.json", "/var/lib/pm/files.json", "/var/lib/pm/container-factory-version", "/var/lib/pm/sbom-sources.json"}, name)
}

func componentSource(component cdx.Component) (shared.BuildSource, bool) {
	var source shared.BuildSource
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "dk:source" {
				err := json.Unmarshal([]byte(prop.Value), &source)
				return source, err == nil
			}
		}
	}
	return source, false
}

func sourceIdentity(source shared.BuildSource) string {
	return source.Kind + "\n" + source.Locator + "\n" + source.Checksum
}

func ValidateImageSource(ctx context.Context, filename, kind string, bom *cdx.BOM, platform string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if bom == nil || bom.Metadata == nil || bom.Metadata.Properties == nil || bom.Components == nil {
		return fmt.Errorf("%s: no-data: %s image has no instrumented SBOM", filename, kind)
	}
	verified, matched := false, false
	for _, property := range *bom.Metadata.Properties {
		if property.Name == verificationProperty && property.Value == verifiedImage {
			verified = true
		}
		if property.Name == "dk:platform" && property.Value == platform {
			matched = true
		}
	}
	if !verified || !matched {
		return fmt.Errorf("%s: no-data: %s image SBOM is unverified or has a different platform", filename, kind)
	}
	return nil
}
