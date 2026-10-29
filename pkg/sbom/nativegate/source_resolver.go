package nativegate

import (
	"context"
	"fmt"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/werf/werf/v3/pkg/docker_registry"
	ospm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

// resolvedSource is one source receipt entry bound to the original package it pins.
// Source keeps the producer's entry, Packet bytes included, exactly as it arrived.
type resolvedSource struct {
	ID       string
	Source   sources.Source
	Package  ospm.PmPackageInfo
	Original *original.OriginalPackage
}

// resolveOriginalSource fetches the one original package a source entry pins.
//
// The entry is taken as written: the repository must already be canonical, and the
// platform must name an explicit target the package declares. Nothing here widens that
// to the host platform, to a registry default, or to the first matching descendant of an
// index — the pinned manifest is fetched once and dispatched on its own media type, so
// an index resolves by unique platform match and an image is checked against the digest
// it was pinned by.
//
// A source that cannot be resolved is no-data rather than a partial answer: the returned
// package is complete and verified, or there is no result at all. Caching belongs to the
// caller; every call fetches.
func resolveOriginalSource(ctx context.Context, source sources.Source) (*resolvedSource, error) {
	repo, err := name.NewRepository(source.Registry, name.StrictValidation)
	if err != nil {
		return nil, fmt.Errorf("source registry %q: %w", source.Registry, err)
	}
	if repo.Name() != source.Registry {
		return nil, fmt.Errorf("source registry %q is not canonical, expected %q", source.Registry, repo.Name())
	}

	platform, err := v1.ParsePlatform(source.Platform)
	if err != nil {
		return nil, fmt.Errorf("source platform %q: %w", source.Platform, err)
	}
	if platform.String() != source.Platform || platform.OSVersion != "" {
		return nil, fmt.Errorf("source platform %q is not an explicit os/arch[/variant] target", source.Platform)
	}

	metadata, err := readSourcePackage(source)
	if err != nil {
		return nil, err
	}

	pin, err := original.PinnedDigest(metadata.Name, metadata.Version, metadata.Arch, metadata.Digest, *platform)
	if err != nil {
		return nil, err
	}

	pkg, err := fetchOriginalPackage(ctx, repo, pin, *platform)
	if err != nil {
		return nil, err
	}

	return &resolvedSource{
		ID:       originalSourceID(repo.Name(), pin, *platform),
		Source:   source,
		Package:  metadata,
		Original: pkg,
	}, nil
}

// originalSourceID names what was fetched and verified — the canonical repository, the
// pinned manifest digest and the target platform — and nothing else. Receipt entries that
// differ only in Packet whitespace or in metadata no verification reads keep one id,
// while a different repository, pin or platform never collapses onto it.
func originalSourceID(repo string, pin v1.Hash, platform v1.Platform) string {
	return "pm-source:" + digest([]byte(repo+"\n"+pin.String()+"\n"+platform.String()))
}

func fetchOriginalPackage(ctx context.Context, repo name.Repository, pin v1.Hash, platform v1.Platform) (*original.OriginalPackage, error) {
	reference := repo.Digest(pin.String())
	options := append([]remote.Option{remote.WithContext(ctx)}, docker_registry.API().RemoteOptionsForHost(ctx, repo.RegistryStr())...)
	desc, err := remote.Get(reference, options...)
	if err != nil {
		return nil, fmt.Errorf("no-data: original %s: %w", reference, err)
	}

	image, err := originalImage(desc, pin, platform)
	if err != nil {
		return nil, fmt.Errorf("no-data: original %s: %w", reference, err)
	}

	pkg, err := original.NewOriginalPackage(image)
	if err != nil {
		return nil, fmt.Errorf("no-data: original %s: %w", reference, err)
	}
	if !pkg.Complete() {
		return nil, fmt.Errorf("no-data: original %s holds no verified view", reference)
	}

	return pkg, nil
}

func originalImage(desc *remote.Descriptor, pin v1.Hash, platform v1.Platform) (v1.Image, error) {
	switch {
	case desc.MediaType.IsIndex():
		index, err := desc.ImageIndex()
		if err != nil {
			return nil, err
		}

		return original.SelectImage(index, pin, platform)
	case desc.MediaType.IsImage():
		image, err := desc.Image()
		if err != nil {
			return nil, err
		}
		if err := original.ValidateImage(image, pin, platform); err != nil {
			return nil, err
		}

		return image, nil
	}

	return nil, fmt.Errorf("unsupported media type %s", desc.MediaType)
}
