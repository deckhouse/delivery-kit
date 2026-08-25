package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/werf/werf/v2/pkg/container_backend/thirdparty/platformutil"
	"github.com/werf/werf/v2/pkg/docker_registry"
)

// ErrIndexPlatformRequired is returned when a digest points to a multi-platform
// image index and no platform was specified to disambiguate it.
var ErrIndexPlatformRequired = errors.New("image is a multi-platform index, platform required")

// PlatformDigest pairs a platform string (e.g. "linux/amd64") with the digest
// of the corresponding platform manifest inside an image index.
type PlatformDigest struct {
	Platform string
	Digest   string
}

// NormalizePlatform parses and normalizes a user-supplied platform string
// (e.g. "linux/arm64/v8" → "linux/arm64"). An empty input stays empty.
func NormalizePlatform(platform string) (string, error) {
	if platform == "" {
		return "", nil
	}
	normalized, err := platformutil.NormalizeUserParams([]string{platform})
	if err != nil {
		return "", fmt.Errorf("parse platform %q: %w", platform, err)
	}
	return normalized[0], nil
}

// PlatformMatches reports whether an index entry platform satisfies the
// requested platform: either exactly, or as a variant of a requested
// "os/arch" pair (e.g. entry "linux/arm/v7" matches request "linux/arm").
func PlatformMatches(entryPlatform, requested string) bool {
	if entryPlatform == requested {
		return true
	}
	return strings.Count(requested, "/") == 1 && strings.HasPrefix(entryPlatform, requested+"/")
}

// ResolvePlatformDigest resolves a digest that may point to a multi-platform image
// index into the digest of a concrete platform manifest. For an index, platform
// selects the matching manifest; an empty platform yields an error (wrapping
// ErrIndexPlatformRequired) listing the available platforms and their digests.
// A non-index digest is returned unchanged; if platform is set, it is validated
// against the manifest's config platform and a mismatch is an error.
func ResolvePlatformDigest(ctx context.Context, repo, digestStr, platform string) (string, error) {
	platform, err := NormalizePlatform(platform)
	if err != nil {
		return "", err
	}

	desc, err := getManifestDescriptor(ctx, repo, digestStr)
	if err != nil {
		return "", err
	}

	if !desc.MediaType.IsIndex() {
		if platform == "" {
			return digestStr, nil
		}
		if err := verifyManifestPlatform(desc, digestStr, platform); err != nil {
			return "", err
		}
		return digestStr, nil
	}

	entries, err := indexPlatformDigests(desc, repo, digestStr)
	if err != nil {
		return "", err
	}
	return matchPlatformDigest(entries, platform)
}

// IsIndexReference reports whether the digest points to a multi-platform image index.
func IsIndexReference(ctx context.Context, repo, digestStr string) (bool, error) {
	desc, err := getManifestDescriptor(ctx, repo, digestStr)
	if err != nil {
		return false, err
	}
	return desc.MediaType.IsIndex(), nil
}

// ListIndexPlatforms returns the platform manifests of an image index. For a
// non-index manifest it returns a single entry with an empty Platform and the
// digest itself. When no remote options are given, per-host defaults from
// docker_registry are used.
func ListIndexPlatforms(ctx context.Context, repo, digestStr string, opts ...remote.Option) ([]PlatformDigest, error) {
	desc, err := getManifestDescriptor(ctx, repo, digestStr, opts...)
	if err != nil {
		return nil, err
	}

	if !desc.MediaType.IsIndex() {
		return []PlatformDigest{{Platform: "", Digest: digestStr}}, nil
	}

	return indexPlatformDigests(desc, repo, digestStr)
}

func getManifestDescriptor(ctx context.Context, repo, digestStr string, opts ...remote.Option) (*remote.Descriptor, error) {
	ref, err := name.NewDigest(repo + "@" + digestStr)
	if err != nil {
		return nil, fmt.Errorf("parse digest reference %q: %w", repo+"@"+digestStr, err)
	}

	if len(opts) == 0 {
		opts = docker_registry.API().RemoteOptionsForHost(ctx, repo)
	}
	opts = append([]remote.Option{remote.WithContext(ctx)}, opts...)
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("get manifest %q: %w", ref.String(), err)
	}
	return desc, nil
}

func indexPlatformDigests(desc *remote.Descriptor, repo, digestStr string) ([]PlatformDigest, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read image index %q: %w", repo+"@"+digestStr, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest %q: %w", repo+"@"+digestStr, err)
	}
	return platformDigestsFromIndexManifest(im), nil
}

func verifyManifestPlatform(desc *remote.Descriptor, digestStr, platform string) error {
	img, err := desc.Image()
	if err != nil {
		return fmt.Errorf("read image manifest %q: %w", digestStr, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("read image config %q: %w", digestStr, err)
	}
	if cf.OS == "" {
		return nil
	}

	manifestPlatform := v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}.String()
	return checkManifestPlatform(manifestPlatform, digestStr, platform)
}

func checkManifestPlatform(manifestPlatform, digestStr, requested string) error {
	if PlatformMatches(manifestPlatform, requested) {
		return nil
	}
	return fmt.Errorf("image %s is a single-platform %s image, requested platform %s does not match", digestStr, manifestPlatform, requested)
}

func platformDigestsFromIndexManifest(im *v1.IndexManifest) []PlatformDigest {
	var entries []PlatformDigest
	for _, m := range im.Manifests {
		if m.Platform == nil || m.Platform.OS == "" || m.Platform.OS == "unknown" {
			continue
		}
		entries = append(entries, PlatformDigest{
			Platform: m.Platform.String(),
			Digest:   m.Digest.String(),
		})
	}
	return entries
}

func matchPlatformDigest(entries []PlatformDigest, platform string) (string, error) {
	if platform == "" {
		return "", fmt.Errorf("%w; available platforms:\n%s", ErrIndexPlatformRequired, formatPlatformDigests(entries))
	}

	var osArchMatches []PlatformDigest
	for _, entry := range entries {
		if entry.Platform == platform {
			return entry.Digest, nil
		}
		if PlatformMatches(entry.Platform, platform) {
			osArchMatches = append(osArchMatches, entry)
		}
	}

	if len(osArchMatches) == 1 {
		return osArchMatches[0].Digest, nil
	}
	if len(osArchMatches) > 1 {
		return "", fmt.Errorf("platform %q is ambiguous; available platforms:\n%s", platform, formatPlatformDigests(entries))
	}

	return "", fmt.Errorf("platform %q not found in image index; available platforms:\n%s", platform, formatPlatformDigests(entries))
}

func formatPlatformDigests(entries []PlatformDigest) string {
	if len(entries) == 0 {
		return "  (none)"
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, fmt.Sprintf("  %s → %s", entry.Platform, entry.Digest))
	}
	return strings.Join(lines, "\n")
}
