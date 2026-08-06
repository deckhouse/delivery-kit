package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

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

// ResolvePlatformDigest resolves a digest that may point to a multi-platform image
// index into the digest of a concrete platform manifest. A non-index digest is
// returned unchanged. For an index, platform selects the matching manifest; an
// empty platform yields an error (wrapping ErrIndexPlatformRequired) listing the
// available platforms and their digests.
func ResolvePlatformDigest(ctx context.Context, repo, digestStr, platform string) (string, error) {
	entries, isIndex, err := fetchIndexPlatforms(ctx, repo, digestStr)
	if err != nil {
		return "", err
	}
	if !isIndex {
		return digestStr, nil
	}
	return matchPlatformDigest(entries, platform)
}

// ListIndexPlatforms returns the platform manifests of an image index. For a
// non-index manifest it returns a single entry with an empty Platform and the
// digest itself.
func ListIndexPlatforms(ctx context.Context, repo, digestStr string) ([]PlatformDigest, error) {
	entries, isIndex, err := fetchIndexPlatforms(ctx, repo, digestStr)
	if err != nil {
		return nil, err
	}
	if !isIndex {
		return []PlatformDigest{{Platform: "", Digest: digestStr}}, nil
	}
	return entries, nil
}

func fetchIndexPlatforms(ctx context.Context, repo, digestStr string) ([]PlatformDigest, bool, error) {
	ref, err := name.NewDigest(repo + "@" + digestStr)
	if err != nil {
		return nil, false, fmt.Errorf("parse digest reference %q: %w", repo+"@"+digestStr, err)
	}

	opts := append([]remote.Option{remote.WithContext(ctx)}, docker_registry.API().RemoteOptionsForHost(ctx, repo)...)
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, false, fmt.Errorf("get manifest %q: %w", ref.String(), err)
	}

	if !desc.MediaType.IsIndex() {
		return nil, false, nil
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, false, fmt.Errorf("read image index %q: %w", ref.String(), err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, false, fmt.Errorf("read index manifest %q: %w", ref.String(), err)
	}

	return platformDigestsFromIndexManifest(im), true, nil
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
		if strings.HasPrefix(entry.Platform, platform+"/") {
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
