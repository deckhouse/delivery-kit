package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/slug"
)

const (
	FallbackTagPrefix    = "sha256-"
	EmptyConfigMediaType = "application/vnd.oci.empty.v1+json"

	digestHexLen = 64
)

// fallbackTagImageNameMaxSize is the budget left for the encoded image name in
// a fallback tag: the docker tag limit minus the prefix, the digest hex and the
// separator.
var fallbackTagImageNameMaxSize = slug.DockerTagMaxSize - len(FallbackTagPrefix) - digestHexLen - 1

var (
	tagMutexes    map[string]*sync.Mutex
	tagMutexGuard sync.Mutex
)

func getTagMutex(key string) *sync.Mutex {
	tagMutexGuard.Lock()
	defer tagMutexGuard.Unlock()

	if tagMutexes == nil {
		tagMutexes = make(map[string]*sync.Mutex)
	}
	m, ok := tagMutexes[key]
	if !ok {
		m = &sync.Mutex{}
		tagMutexes[key] = m
	}
	return m
}

func tagMutexKey(repo, parentDigest, imageName string) string {
	return repo + "/" + FallbackTag(parentDigest, imageName)
}

// FallbackTag returns the tag of the artifact index holding the artifacts of a
// single image.
//
// The tag is keyed by both the parent digest and the image name. Two werf images
// with identical content share one digest, so a digest-only tag would make them
// share a single mutable index: concurrent attaches would then read the same
// index state and overwrite each other's entries.
//
// An empty image name keeps the digest-only form, which is also the form written
// by previous werf versions.
func FallbackTag(parentDigest, imageName string) string {
	if imageName == "" {
		return FallbackTagPrefix + fallbackTagDigestHex(parentDigest)
	}

	return FallbackTagDigestPrefix(parentDigest) + slug.LimitedSlug(imageName, fallbackTagImageNameMaxSize)
}

// FallbackTagDigestPrefix returns the prefix shared by the fallback tags of all
// named images attached to the given parent digest.
func FallbackTagDigestPrefix(parentDigest string) string {
	return FallbackTagPrefix + fallbackTagDigestHex(parentDigest) + "-"
}

// ParseFallbackTagDigest extracts the parent digest from a fallback tag. Both the
// per-image form and the digest-only form written by previous werf versions are
// recognized, so that cleanup keeps collecting indexes of either kind.
func ParseFallbackTagDigest(tag string) (string, bool) {
	rest, found := strings.CutPrefix(tag, FallbackTagPrefix)
	if !found || len(rest) < digestHexLen {
		return "", false
	}

	hex := rest[:digestHexLen]
	if strings.Trim(hex, "0123456789abcdef") != "" {
		return "", false
	}
	if len(rest) > digestHexLen && rest[digestHexLen] != '-' {
		return "", false
	}

	return "sha256:" + hex, true
}

func isFallbackTagForDigest(tag, parentDigest string) bool {
	hex := fallbackTagDigestHex(parentDigest)
	return tag == FallbackTagPrefix+hex || strings.HasPrefix(tag, FallbackTagPrefix+hex+"-")
}

func fallbackTagDigestHex(parentDigest string) string {
	hex, err := DigestHex(parentDigest)
	if err != nil {
		hex = strings.TrimPrefix(parentDigest, "sha256:")
		return strings.NewReplacer(":", "-", "/", "_", "@", "-").Replace(hex)
	}

	return hex
}

func Attach(ctx context.Context, repo, parentDigest string, artifactDesc v1.Descriptor, artifactType, imageName string, opts ...remote.Option) error {
	m := getTagMutex(tagMutexKey(repo, parentDigest, imageName))
	m.Lock()
	defer m.Unlock()

	// RMW: read current index, update, push
	current, err := pullFallbackIndex(ctx, repo, parentDigest, imageName, opts...)
	if err != nil {
		return fmt.Errorf("pull fallback index before attach: %w", err)
	}

	next := updateFallbackIndex(current, artifactDesc, artifactType, imageName)
	if err := pushFallbackIndex(ctx, repo, parentDigest, imageName, next, opts...); err != nil {
		return fmt.Errorf("push fallback index: %w", err)
	}

	return waitForConsistency(ctx, repo, parentDigest, imageName, next, opts...)
}

func waitForConsistency(ctx context.Context, repo, parentDigest, imageName string, next v1.ImageIndex, opts ...remote.Option) error {
	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = 500 * time.Millisecond

	notify := func(err error, duration time.Duration) {
		logboek.Context(ctx).Warn().LogF("SBOM attach consistency wait failed: %s. Retrying in %v...\n", err, duration)
	}

	_, err := backoff.Retry(ctx, func() (bool, error) {
		verified, err := pullFallbackIndex(ctx, repo, parentDigest, imageName, opts...)
		if err != nil {
			return false, err
		}

		verifiedDigest, err := verified.Digest()
		if err != nil {
			return false, fmt.Errorf("get fallback index digest: %w", err)
		}
		nextDigest, err := next.Digest()
		if err != nil {
			return false, fmt.Errorf("get updated index digest: %w", err)
		}

		if verifiedDigest != nextDigest {
			return false, fmt.Errorf("consistency check failed: digest mismatch")
		}

		return true, nil
	},
		backoff.WithBackOff(eb),
		backoff.WithMaxElapsedTime(30*time.Second),
		backoff.WithNotify(notify),
	)
	return err
}

func GetAttached(ctx context.Context, repo, parentDigest, artifactType, imageName string, opts ...remote.Option) (v1.Descriptor, bool, error) {
	var (
		idx v1.ImageIndex
		err error
	)
	if imageName == "" {
		idx, err = PullFallbackIndex(ctx, repo, parentDigest, opts...)
	} else {
		idx, err = pullFallbackIndex(ctx, repo, parentDigest, imageName, opts...)
	}
	if err != nil {
		return v1.Descriptor{}, false, err
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return v1.Descriptor{}, false, fmt.Errorf("read fallback index manifest: %w", err)
	}

	var matches []v1.Descriptor
	for _, desc := range im.Manifests {
		if desc.ArtifactType != artifactType {
			continue
		}
		if imageName != "" && desc.Annotations[image.WerfImageNameAnnotation] != imageName {
			continue
		}
		matches = append(matches, desc)
	}

	if len(matches) == 0 {
		return v1.Descriptor{}, false, nil
	}

	if imageName == "" && len(matches) > 1 {
		logboek.Context(ctx).Warn().LogF("WARNING: multiple artifact entries (imageName not specified, found %d entries for digest %q)\n", len(matches), parentDigest)
	}

	return matches[0], true, nil
}

func PushArtifactImage(ctx context.Context, repo string, img v1.Image, opts ...remote.Option) error {
	imgDigest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("compute artifact image digest: %w", err)
	}

	targetRef, err := name.NewDigest(repo + "@" + imgDigest.String())
	if err != nil {
		return fmt.Errorf("parse artifact digest reference: %w", err)
	}
	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	if err := remote.Write(targetRef, img, ropts...); err != nil {
		return fmt.Errorf("push artifact manifest: %w", err)
	}

	return nil
}

// PullFallbackIndex returns the combined artifact index of every image attached
// to the given parent digest. Each image keeps its own index, so the entries of
// all of them are merged into a single read-only view.
func PullFallbackIndex(ctx context.Context, repo, parentDigest string, opts ...remote.Option) (v1.ImageIndex, error) {
	tags, err := listFallbackTags(ctx, repo, parentDigest, opts...)
	if err != nil {
		return nil, err
	}

	var manifests []v1.Descriptor
	for _, tag := range tags {
		idx, err := pullFallbackIndexByTag(ctx, repo, tag, opts...)
		if err != nil {
			return nil, err
		}

		im, err := idx.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("read fallback index manifest: %w", err)
		}

		manifests = append(manifests, im.Manifests...)
	}

	if len(manifests) == 0 {
		return empty.Index, nil
	}

	return newStaticIndex(manifests), nil
}

func listFallbackTags(ctx context.Context, repo, parentDigest string, opts ...remote.Option) ([]string, error) {
	repoRef, err := name.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("parse repository reference: %w", err)
	}

	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	tags, err := remote.List(repoRef, ropts...)
	if err != nil {
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("list repository tags: %w", err)
	}

	return lo.Filter(tags, func(tag string, _ int) bool {
		return isFallbackTagForDigest(tag, parentDigest)
	}), nil
}

func pullFallbackIndex(ctx context.Context, repo, parentDigest, imageName string, opts ...remote.Option) (v1.ImageIndex, error) {
	return pullFallbackIndexByTag(ctx, repo, FallbackTag(parentDigest, imageName), opts...)
}

func pullFallbackIndexByTag(ctx context.Context, repo, tag string, opts ...remote.Option) (v1.ImageIndex, error) {
	tagRef, err := name.NewTag(repo + ":" + tag)
	if err != nil {
		return nil, fmt.Errorf("parse fallback tag reference: %w", err)
	}

	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	idx, err := remote.Index(tagRef, ropts...)
	if err != nil {
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == 404 {
			return empty.Index, nil
		}
		return nil, fmt.Errorf("pull fallback index: %w", err)
	}

	return idx, nil
}

func pushFallbackIndex(ctx context.Context, repo, parentDigest, imageName string, idx v1.ImageIndex, opts ...remote.Option) error {
	tagRef, err := name.NewTag(repo + ":" + FallbackTag(parentDigest, imageName))
	if err != nil {
		return fmt.Errorf("parse fallback tag reference: %w", err)
	}

	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	if err := remote.WriteIndex(tagRef, idx, ropts...); err != nil {
		return fmt.Errorf("push fallback index: %w", err)
	}

	return nil
}

func updateFallbackIndex(current v1.ImageIndex, artifactDesc v1.Descriptor, artifactType, imageName string) v1.ImageIndex {
	im, err := current.IndexManifest()
	if err != nil || im == nil {
		return newStaticIndex([]v1.Descriptor{artifactDesc})
	}

	kept := make([]v1.Descriptor, 0, len(im.Manifests)+1)
	for _, manifest := range im.Manifests {
		if manifest.ArtifactType == artifactType {
			existingImageName := manifest.Annotations[image.WerfImageNameAnnotation]
			if imageName != "" && existingImageName == imageName {
				continue
			}
			if imageName == "" && existingImageName == "" {
				continue
			}
		}
		kept = append(kept, manifest)
	}
	kept = append(kept, artifactDesc)

	return newStaticIndex(kept)
}

type staticIndex struct {
	manifest *v1.IndexManifest
	raw      []byte
}

func newStaticIndex(manifests []v1.Descriptor) v1.ImageIndex {
	im := &v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     manifests,
	}

	raw, err := json.Marshal(im)
	if err != nil {
		panic(err)
	}

	return &staticIndex{manifest: im, raw: raw}
}

func (i *staticIndex) MediaType() (types.MediaType, error) {
	return types.OCIImageIndex, nil
}

func (i *staticIndex) Digest() (v1.Hash, error) {
	hash, _, err := v1.SHA256(bytes.NewReader(i.raw))
	if err != nil {
		return v1.Hash{}, fmt.Errorf("compute index digest: %w", err)
	}
	return hash, nil
}

func (i *staticIndex) Size() (int64, error) {
	return int64(len(i.raw)), nil
}

func (i *staticIndex) IndexManifest() (*v1.IndexManifest, error) {
	return i.manifest.DeepCopy(), nil
}

func (i *staticIndex) RawManifest() ([]byte, error) {
	return append([]byte(nil), i.raw...), nil
}

func (i *staticIndex) Image(v1.Hash) (v1.Image, error) {
	return nil, fmt.Errorf("image lookup unsupported")
}

func (i *staticIndex) ImageIndex(v1.Hash) (v1.ImageIndex, error) {
	return nil, fmt.Errorf("nested index lookup unsupported")
}

func (i *staticIndex) Manifests() ([]partial.Describable, error) {
	return nil, nil
}

var ErrNotFound = fmt.Errorf("artifact not found")
