package nativegate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type PackageSet struct {
	resolved   []*resolvedSource
	Originals  []Original
	Components []cdx.Component
	Symlinks   map[string]string
}

type ContextOptions struct {
	Subject       string
	Platform      string
	UserRoots     []string
	ContainerRoot string
}

func (set *PackageSet) IncludeImage(ctx context.Context, bom *cdx.BOM, originals []Original, platform string, trusted TrustedPackages) error {
	if err := ValidateImageSource(ctx, "/", "source", bom, platform); err != nil {
		return err
	}
	receipt := &sources.Receipt{Version: sources.Version, Sources: []sources.Source{}}
	seenSources := map[string]bool{}
	for _, component := range *bom.Components {
		source, ok := componentSource(component)
		if !ok || source.Kind != "pm" || seenSources[sourceIdentity(source)] {
			continue
		}
		if slices.ContainsFunc(set.resolved, func(item *resolvedSource) bool {
			return item.Source.Registry == source.Locator && item.Package.Digest == source.Checksum
		}) {
			continue
		}
		seenSources[sourceIdentity(source)] = true
		var packet json.RawMessage
		for _, property := range *component.Properties {
			if property.Name == "dk:pm-packet" {
				packet = json.RawMessage(property.Value)
			}
		}
		if len(packet) == 0 {
			return fmt.Errorf("%s: no-data: package metadata absent in source SBOM", component.Name)
		}
		candidate := sources.Source{Registry: source.Locator, Platform: platform, Packet: packet}
		metadata, err := readSourcePackage(candidate)
		if err != nil {
			return err
		}
		if metadata.Digest != source.Checksum || metadata.Name != component.Name || metadata.Version != component.Version {
			return fmt.Errorf("%s: package metadata contradicts source SBOM", component.Name)
		}
		receipt.Sources = append(receipt.Sources, candidate)
	}
	opened, err := OpenPackageSet(ctx, receipt, platform, trusted)
	if err != nil {
		return err
	}
	set.resolved = append(set.resolved, opened.resolved...)
	set.Components = append(set.Components, opened.Components...)
	set.Originals = append(set.Originals, originals...)
	return nil
}

func UserSourceRoots(ctx context.Context, mappings []string, workdir, tmpdir string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	roots := slices.Clone(mappings)
	for _, root := range roots {
		if root == "/" || !path.IsAbs(root) || path.Clean(root) != root {
			return nil, fmt.Errorf("invalid git source root %q", root)
		}
	}
	system := []string{"/usr", "/lib", "/lib32", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/var/lib/pm"}
	for _, root := range []string{workdir, tmpdir} {
		if root == "" || root == "/" || userFile(root, system) {
			continue
		}
		if !path.IsAbs(root) || path.Clean(root) != root {
			return nil, fmt.Errorf("invalid stage source root %q", root)
		}
		roots = appendUnique(roots, root)
	}
	slices.Sort(roots)
	return slices.Compact(roots), nil
}

func OpenPackageSet(ctx context.Context, receipt *sources.Receipt, platform string, trusted TrustedPackages) (*PackageSet, error) {
	result := &PackageSet{Symlinks: map[string]string{}}
	if receipt == nil {
		return nil, fmt.Errorf("no-data: missing pm source command result")
	}
	for _, source := range receipt.Sources {
		identity, err := parseOriginalSourceIdentity(source)
		if err != nil {
			return nil, err
		}
		if source.Platform != platform {
			return nil, fmt.Errorf("%s: package platform %s differs from %s", identity.Package.Name, source.Platform, platform)
		}
		authoritative, known := trusted[source.Registry+"@"+identity.Pin.String()]
		if !known {
			return nil, fmt.Errorf("%s: no-data: package outside instrumented index", identity.Package.Name)
		}
		if authoritative.Name != identity.Package.Name || authoritative.Version != identity.Package.Version || !slices.Contains(authoritative.Arch, platform) {
			return nil, fmt.Errorf("%s: package identity contradicts instrumented index", identity.Package.Name)
		}
		resolved, err := resolveOriginalSource(ctx, source)
		if err != nil {
			return nil, err
		}
		component, err := embeddedComponent(shared.BuildComponent{ID: resolved.ID, Name: identity.Package.Name, Version: identity.Package.Version, Source: shared.BuildSource{Kind: "pm", Locator: source.Registry, Checksum: identity.Pin.String()}})
		if err != nil {
			return nil, err
		}
		*component.Properties = append(*component.Properties, cdx.Property{Name: "dk:pm-packet", Value: string(source.Packet)}, cdx.Property{Name: "dk:pm-platform", Value: source.Platform})
		result.Components = append(result.Components, component)
		result.resolved = append(result.resolved, resolved)
		originalImage, err := resolved.Root.verifiedImage(identity.Platform)
		if err != nil {
			return nil, err
		}
		originalIndex, err := shippedscope.IndexImageFiles(ctx, originalImage)
		if err != nil {
			return nil, fmt.Errorf("index package %s links: %w", identity.Package.Name, err)
		}
		if originalIndex.Incomplete {
			return nil, fmt.Errorf("%s: incomplete package file index", identity.Package.Name)
		}
		for name, target := range originalIndex.Symlinks {
			if previous, exists := result.Symlinks[name]; exists && previous != target {
				return nil, fmt.Errorf("%s: ambiguous package symlink", name)
			}
			result.Symlinks[name] = target
		}
		for _, entry := range resolved.Original.Entries() {
			if !entry.Mode.IsRegular() {
				continue
			}
			if entry.Err != nil || entry.SHA256 == "" {
				return nil, fmt.Errorf("/%s: no-data: incomplete original package file", entry.Path)
			}
			result.Originals = append(result.Originals, Original{Path: "/" + entry.Path, SourcePath: entry.Path, SHA256: entry.SHA256, Component: component, Kind: "pm"})
		}
	}
	return result, nil
}

func MaterializeBuildContext(ctx context.Context, img v1.Image, packages *PackageSet, directory string, opts ContextOptions) (string, error) {
	if !path.IsAbs(opts.ContainerRoot) || path.Clean(opts.ContainerRoot) != opts.ContainerRoot {
		return "", fmt.Errorf("invalid container context root %q", opts.ContainerRoot)
	}
	if opts.Platform != "linux/amd64" && opts.Platform != "linux/arm64" {
		return "", fmt.Errorf("unsupported platform %s", opts.Platform)
	}
	index, err := shippedscope.IndexImageFiles(ctx, img)
	if err != nil {
		return "", fmt.Errorf("index build context image: %w", err)
	}
	if index.Incomplete {
		return "", fmt.Errorf("no-data: incomplete build context image")
	}
	if err := verifySymlinkOriginals(&filesystem{index: index}, packages.Symlinks); err != nil {
		return "", err
	}
	if err := validateBootstrapInputs(ctx, img, packages, opts.Platform); err != nil {
		return "", err
	}
	bindings := slices.Clone(packages.Originals)
	for position, binding := range bindings {
		if binding.Kind != "bootstrap" {
			continue
		}
		matched, err := matchPackageOriginal(binding.Path, binding.SHA256, packages.Originals)
		if err != nil {
			return "", err
		}
		if matched != nil {
			matched.Path = binding.Path
			bindings[position] = *matched
		}
	}
	known := map[string]bool{}
	for _, binding := range bindings {
		filename, err := resolveRegularOriginal(&filesystem{index: index}, binding.Path)
		if err != nil {
			return "", err
		}
		known[filename] = true
	}
	for filename, file := range index.Files {
		if known[filename] {
			continue
		}
		matched, err := matchPackageOriginal(filename, file.Digest, packages.Originals)
		if err != nil {
			return "", err
		}
		if matched != nil {
			matched.Path = filename
			bindings = append(bindings, *matched)
		}
	}
	declaration := &buildcontext.Context{Version: 1, Platform: opts.Platform, Subject: shared.BuildComponent{ID: "app", Name: opts.Subject, Version: "unspecified", Source: shared.BuildSource{Kind: "declared", Locator: "dk:image:" + opts.Subject}}, OwnRoots: opts.UserRoots, Packages: []buildcontext.Package{}, Imports: []buildcontext.Import{}}
	seen := map[string]buildcontext.Import{}
	for position, resolved := range packages.resolved {
		name := strings.TrimPrefix(digest([]byte(resolved.ID)), "sha256:")
		target, err := layout.Write(filepath.Join(directory, "originals", name), empty.Index)
		if err != nil {
			return "", fmt.Errorf("create original layout: %w", err)
		}
		if resolved.Root.Index != nil {
			err = target.AppendIndex(resolved.Root.Index)
		} else {
			err = target.AppendImage(resolved.Root.Image)
		}
		if err != nil {
			return "", fmt.Errorf("export original %s: %w", resolved.ID, err)
		}
		declaration.Packages = append(declaration.Packages, buildcontext.Package{Registry: resolved.Source.Registry, Platform: resolved.Source.Platform, Packet: resolved.Source.Packet, Layout: path.Join(opts.ContainerRoot, "originals", name)})
		for _, binding := range bindings {
			source, ok := componentSource(binding.Component)
			if !ok || source.Kind != "pm" || source.Locator != resolved.Source.Registry || source.Checksum != resolved.Package.Digest {
				continue
			}
			entry, err := resolved.Original.Lookup(binding.SourcePath)
			if err != nil {
				return "", fmt.Errorf("%s: resolve original %s: %w", binding.Path, binding.SourcePath, err)
			}
			filename, err := resolveRegularOriginal(&filesystem{index: index}, binding.Path)
			if err != nil {
				return "", err
			}
			file, exists := index.Files[filename]
			if !exists {
				continue
			}
			if file.Digest != entry.SHA256 {
				return "", fmt.Errorf("%s: hash-mismatch: installed package source changed", filename)
			}
			if previous, exists := seen[filename]; exists {
				if *previous.Package == position && previous.OriginalPath == binding.SourcePath {
					continue
				}
				return "", fmt.Errorf("%s: ambiguous package source", filename)
			}
			seen[filename] = buildcontext.Import{Path: filename, Package: lo.ToPtr(position), OriginalPath: binding.SourcePath}
			declaration.Imports = append(declaration.Imports, buildcontext.Import{Path: filename, Package: lo.ToPtr(position), OriginalPath: binding.SourcePath})
		}
	}
	data, err := buildcontext.Encode(declaration)
	if err != nil {
		return "", fmt.Errorf("encode build context: %w", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "context.json"), data, 0o444); err != nil {
		return "", fmt.Errorf("write build context: %w", err)
	}
	return path.Join(opts.ContainerRoot, "context.json"), nil
}
