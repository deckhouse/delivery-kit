package nativegate

import (
	"bytes"
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
	fs, err := readFilesystem(ctx, img)
	if err != nil {
		return fmt.Errorf("read image filesystem: %w", err)
	}
	if err := verifySymlinkOriginals(fs, opts.ExpectedSymlinks); err != nil {
		return err
	}

	originals := make(map[string]Original)
	trusted := make(map[string]bool)
	for _, component := range opts.TrustedComponents {
		if source, ok := componentSource(component); ok {
			trusted[sourceIdentity(source)] = true
		}
	}
	for _, original := range opts.Originals {
		if servicePath(original.Path) {
			continue
		}
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
		resolved, err := resolveRegularOriginal(fs, original.Path)
		if err != nil {
			return err
		}
		if previous, exists := originals[resolved]; exists && (previous.SHA256 != original.SHA256 || previous.Component.BOMRef != original.Component.BOMRef) {
			if original.Kind == "bootstrap" && previous.Kind != "bootstrap" && previous.SHA256 == original.SHA256 {
				continue
			}
			if previous.Kind == "bootstrap" && original.Kind != "bootstrap" && previous.SHA256 == original.SHA256 {
				originals[resolved] = original
				continue
			}
			return fmt.Errorf("%s: ambiguous original ownership", resolved)
		}
		originals[resolved] = original
	}
	policy := strictPolicy(opts.Platform)
	catalog := Catalog{Components: make(map[string]cdx.Component)}
	for _, component := range opts.TrustedComponents {
		catalog.Components[component.BOMRef] = component
	}
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
		if !known || original.Kind == "bootstrap" {
			matched, err := matchPackageOriginal(name, file.Digest, opts.Originals)
			if err != nil {
				return err
			}
			if matched != nil {
				original, known = *matched, true
			}
		}
		ins := inspector{policy: policy, catalog: &catalog}
		source, packageSource := componentSource(original.Component)
		packageArchive := known && packageSource && source.Kind == "pm" && (bytes.HasPrefix(fs.bodies[name], []byte(archiveMagic)) || bytes.HasPrefix(fs.bodies[name], []byte(thinArchiveMagic)))
		var record Record
		var native bool
		if packageArchive {
			native = true
		} else {
			record, native, err = ins.inspect(fs.bodies[name])
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if known && original.Kind == "bootstrap" && !native {
			return fmt.Errorf("%s: no-data: bootstrap output has neither a build record nor a trusted original", name)
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
			if !known && !currentBuildSubject(record, catalog, opts.Subject) {
				return fmt.Errorf("%s: no-data: binary has no matching original or current build subject", name)
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
			if packageArchive {
				record.Origin = "pm"
			}
			record.SourcePath = original.SourcePath
		case native:
			record.Origin = "build"
		case userFile(name, opts.UserRoots):
			ref := "urn:dk:generated:" + opts.Subject
			component, err := embeddedComponent(shared.BuildComponent{ID: "app", Name: opts.Subject, Version: "unspecified", Source: shared.BuildSource{Kind: "declared", Locator: "dk:image:" + opts.Subject}})
			if err != nil {
				return err
			}
			component.BOMRef, component.Type = ref, cdx.ComponentTypeApplication
			*component.Properties = append(*component.Properties, cdx.Property{Name: verificationProperty, Value: "generated"})
			catalog.Components[ref] = component
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

func resolveRegularOriginal(fs *filesystem, name string) (string, error) {
	parent, err := resolvePath(fs, path.Dir(name))
	if err != nil {
		return "", err
	}
	resolved := path.Join(parent, path.Base(name))
	if !servicePath(name) && servicePath(resolved) {
		return "", fmt.Errorf("%s: original resolves into reserved service namespace", name)
	}
	if _, exists := fs.index.Symlinks[resolved]; exists {
		return "", fmt.Errorf("%s: hash-mismatch: regular original replaced by a symlink", name)
	}
	if _, exists := fs.index.Directories[resolved]; exists {
		return "", fmt.Errorf("%s: hash-mismatch: regular original replaced by a directory", name)
	}
	return resolved, nil
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

func verifySymlinkOriginals(fs *filesystem, expected map[string]string) error {
	for _, name := range slices.Sorted(maps.Keys(expected)) {
		if servicePath(name) {
			continue
		}
		parent, err := resolvePath(fs, path.Dir(name))
		if err != nil {
			return err
		}
		resolved := path.Join(parent, path.Base(name))
		if actual, exists := fs.index.Symlinks[resolved]; exists && actual != expected[name] {
			return fmt.Errorf("%s: hash-mismatch: original symlink changed", name)
		}
		if _, exists := fs.index.Files[resolved]; exists {
			return fmt.Errorf("%s: hash-mismatch: original symlink replaced by a file", name)
		}
		if _, exists := fs.index.Directories[resolved]; exists {
			return fmt.Errorf("%s: hash-mismatch: original symlink replaced by a directory", name)
		}
	}
	return nil
}

func matchPackageOriginal(name, hash string, originals []Original) (*Original, error) {
	var result *Original
	seen := map[string]bool{}
	for _, original := range originals {
		source, ok := componentSource(original.Component)
		if original.Kind == "bootstrap" || !ok || source.Kind != "pm" || original.SHA256 != hash {
			continue
		}
		originalPath := original.SourcePath
		if originalPath == "" {
			originalPath = original.Path
		}
		key := sourceIdentity(source) + "\n" + originalPath
		if seen[key] {
			continue
		}
		seen[key] = true
		if result != nil {
			return nil, fmt.Errorf("%s: ambiguous content match for package file", name)
		}
		copy := original
		copy.Kind = "pm"
		result = &copy
	}
	return result, nil
}

func currentBuildSubject(record Record, catalog Catalog, name string) bool {
	current := func(ref string) bool {
		component := catalog.Components[ref]
		source, ok := componentSource(component)
		return ok && source.Kind == "declared" && source.Locator == "dk:image:"+name && component.Name == name
	}
	if record.Archive != nil {
		return !slices.ContainsFunc(record.Archive.Members, func(member ArchiveMember) bool { return !current(member.Subject) })
	}
	return current(record.Subject)
}
