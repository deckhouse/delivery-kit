package nativegate

import (
	"context"
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
}

type ContextOptions struct {
	Subject       string
	Platform      string
	UserRoots     []string
	ContainerRoot string
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

func OpenPackageSet(ctx context.Context, receipt *sources.Receipt, platform string, trusted map[string]bool) (*PackageSet, error) {
	result := &PackageSet{}
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
		if !trusted[source.Registry+"@"+identity.Pin.String()] {
			return nil, fmt.Errorf("%s: no-data: package outside instrumented index", identity.Package.Name)
		}
		resolved, err := resolveOriginalSource(ctx, source)
		if err != nil {
			return nil, err
		}
		component, err := embeddedComponent(shared.BuildComponent{ID: resolved.ID, Name: identity.Package.Name, Version: identity.Package.Version, Source: shared.BuildSource{Kind: "pm", Locator: source.Registry, Checksum: identity.Pin.String()}})
		if err != nil {
			return nil, err
		}
		result.Components = append(result.Components, component)
		result.resolved = append(result.resolved, resolved)
		for _, entry := range resolved.Original.Entries() {
			if !entry.Mode.IsRegular() {
				continue
			}
			if entry.Err != nil || entry.SHA256 == "" {
				return nil, fmt.Errorf("/%s: no-data: incomplete original package file", entry.Path)
			}
			result.Originals = append(result.Originals, Original{Path: "/" + entry.Path, SHA256: entry.SHA256, Component: component, Kind: "pm"})
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
	declaration := &buildcontext.Context{Version: 1, Platform: opts.Platform, Subject: shared.BuildComponent{ID: "app", Name: opts.Subject, Version: "unspecified", Source: shared.BuildSource{Kind: "declared", Locator: "dk:image:" + opts.Subject}}, OwnRoots: opts.UserRoots, Packages: []buildcontext.Package{}, Imports: []buildcontext.Import{}}
	seen := map[string]bool{}
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
		for _, entry := range resolved.Original.Entries() {
			if !entry.Mode.IsRegular() {
				continue
			}
			filename, err := resolvePath(&filesystem{index: index}, "/"+entry.Path)
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
			if seen[filename] {
				return "", fmt.Errorf("%s: ambiguous package source", filename)
			}
			seen[filename] = true
			declaration.Imports = append(declaration.Imports, buildcontext.Import{Path: filename, Package: lo.ToPtr(position), OriginalPath: entry.Path})
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
