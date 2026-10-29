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
	Root     originalRoot
}

// originalRoot keeps the pinned manifest itself — the image or the index the packet
// digest names — beside the image that was selected from it, so that an export can
// carry the identity a consumer looks the package up by rather than the descendant
// platform selection resolved to.
type originalRoot struct {
	Pin   v1.Hash
	Image v1.Image
	Index v1.ImageIndex
}

type originalSourceIdentity struct {
	Repository name.Repository
	Platform   v1.Platform
	Package    ospm.PmPackageInfo
	Pin        v1.Hash
}

func parseOriginalSourceIdentity(source sources.Source) (originalSourceIdentity, error) {
	var result originalSourceIdentity
	repo, err := name.NewRepository(source.Registry, name.StrictValidation)
	if err != nil {
		return result, fmt.Errorf("source registry %q: %w", source.Registry, err)
	}
	if repo.Name() != source.Registry {
		return result, fmt.Errorf("source registry %q is not canonical, expected %q", source.Registry, repo.Name())
	}
	platform, err := v1.ParsePlatform(source.Platform)
	if err != nil {
		return result, fmt.Errorf("source platform %q: %w", source.Platform, err)
	}
	if platform.String() != source.Platform || platform.OSVersion != "" {
		return result, fmt.Errorf("source platform %q is not an explicit os/arch[/variant] target", source.Platform)
	}
	metadata, err := readSourcePackage(source)
	if err != nil {
		return result, err
	}
	pin, err := original.PinnedDigest(metadata.Name, metadata.Version, metadata.Arch, metadata.Digest, *platform)
	if err != nil {
		return result, err
	}
	return originalSourceIdentity{Repository: repo, Platform: *platform, Package: metadata, Pin: pin}, nil
}

func resolveOriginalSource(ctx context.Context, source sources.Source) (*resolvedSource, error) {
	identity, err := parseOriginalSourceIdentity(source)
	if err != nil {
		return nil, err
	}
	pkg, root, err := fetchOriginalPackage(ctx, identity.Repository, identity.Pin, identity.Platform)
	if err != nil {
		return nil, err
	}
	return &resolvedSource{ID: originalSourceID(identity.Repository.Name(), identity.Pin, identity.Platform), Source: source, Package: identity.Package, Original: pkg, Root: root}, nil
}

// originalSourceID names what was fetched and verified — the canonical repository, the
// pinned manifest digest and the target platform — and nothing else. Receipt entries that
// differ only in Packet whitespace or in metadata no verification reads keep one id,
// while a different repository, pin or platform never collapses onto it.
func originalSourceID(repo string, pin v1.Hash, platform v1.Platform) string {
	return "pm-source:" + digest([]byte(repo+"\n"+pin.String()+"\n"+platform.String()))
}

// ReadPinnedOriginalConfig reads the config of the one original image a canonical pinned
// reference names. It is for callers that have the source image digest but no pm packet
// yet, so the identity cannot be checked against packet metadata: the reference must be
// canonical and pinned by digest, the target an explicit Linux platform, and the manifest
// bytes are verified against that digest before the config is read.
//
// Selection is the canonical one — a unique platform match in an index, never the first
// descriptor and never the host — so a multi-arch original resolves to the architecture
// that was asked for or to nothing.
func ReadPinnedOriginalConfig(ctx context.Context, reference, platform string) (*v1.ConfigFile, error) {
	ref, err := name.NewDigest(reference, name.StrictValidation)
	if err != nil {
		return nil, fmt.Errorf("original reference %q: %w", reference, err)
	}
	if ref.Name() != reference {
		return nil, fmt.Errorf("original reference %q is not canonical, expected %q", reference, ref.Name())
	}
	pin, err := v1.NewHash(ref.DigestStr())
	if err != nil || pin.Algorithm != "sha256" || len(pin.Hex) != 64 {
		return nil, fmt.Errorf("original reference %q: invalid pinned digest", reference)
	}
	target, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("original platform %q: %w", platform, err)
	}
	if target.String() != platform || target.OSVersion != "" || target.OS != "linux" || target.Architecture == "" {
		return nil, fmt.Errorf("original platform %q is not an explicit Linux os/arch[/variant] target", platform)
	}

	image, _, err := verifiedOriginalImage(ctx, ref.Context(), pin, *target)
	if err != nil {
		return nil, err
	}

	return image.ConfigFile()
}

func fetchOriginalPackage(ctx context.Context, repo name.Repository, pin v1.Hash, platform v1.Platform) (*original.OriginalPackage, originalRoot, error) {
	image, root, err := verifiedOriginalImage(ctx, repo, pin, platform)
	if err != nil {
		return nil, originalRoot{}, err
	}

	reference := repo.Digest(pin.String())
	pkg, err := original.NewOriginalPackage(image)
	if err != nil {
		return nil, originalRoot{}, fmt.Errorf("no-data: original %s: %w", reference, err)
	}
	if !pkg.Complete() {
		return nil, originalRoot{}, fmt.Errorf("no-data: original %s holds no verified view", reference)
	}

	return pkg, root, nil
}

func verifiedOriginalImage(ctx context.Context, repo name.Repository, pin v1.Hash, platform v1.Platform) (v1.Image, originalRoot, error) {
	reference := repo.Digest(pin.String())
	options := append([]remote.Option{remote.WithContext(ctx)}, docker_registry.API().RemoteOptionsForHost(ctx, repo.RegistryStr())...)
	desc, err := remote.Get(reference, options...)
	if err != nil {
		return nil, originalRoot{}, fmt.Errorf("no-data: original %s: %w", reference, err)
	}

	root, err := pinnedOriginalRoot(desc, pin)
	if err != nil {
		return nil, originalRoot{}, fmt.Errorf("no-data: original %s: %w", reference, err)
	}

	image, err := root.verifiedImage(platform)
	if err != nil {
		return nil, originalRoot{}, fmt.Errorf("no-data: original %s: %w", reference, err)
	}

	return image, root, nil
}

func pinnedOriginalRoot(desc *remote.Descriptor, pin v1.Hash) (originalRoot, error) {
	switch {
	case desc.MediaType.IsIndex():
		index, err := desc.ImageIndex()
		if err != nil {
			return originalRoot{}, err
		}

		return originalRoot{Pin: pin, Index: index}, nil
	case desc.MediaType.IsImage():
		image, err := desc.Image()
		if err != nil {
			return originalRoot{}, err
		}

		return originalRoot{Pin: pin, Image: image}, nil
	}

	return originalRoot{}, fmt.Errorf("unsupported media type %s", desc.MediaType)
}

// verifiedImage resolves the pinned root the way the compile-time consumer does: an
// index resolves by unique platform match, an image is checked against the digest it
// was pinned by. It is not a second selection algorithm.
func (r originalRoot) verifiedImage(platform v1.Platform) (v1.Image, error) {
	if r.Index != nil {
		return original.SelectImage(r.Index, r.Pin, platform)
	}
	if err := original.ValidateImage(r.Image, r.Pin, platform); err != nil {
		return nil, err
	}

	return r.Image, nil
}
