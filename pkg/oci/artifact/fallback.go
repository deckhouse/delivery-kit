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

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/image"
)

const FallbackTagPrefix = "sha256-"

const (
	attachInitialInterval = 500 * time.Millisecond
	attachMaxElapsedTime  = 30 * time.Second
)

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

func tagMutexKey(repo, parentDigest string) string {
	return repo + "/" + FallbackTag(parentDigest)
}

// withTagLock serializes everything that writes the artifact index of a parent
// digest within this process.
//
// It covers the artifact push as well, not only the index update:
// go-containerregistry updates the same index on its own whenever a pushed
// manifest carries a subject, and that update is a read-modify-write no werf
// code takes part in. Leaving it outside the lock lets it overwrite an entry
// another goroutine has just published, and nothing would repair that entry
// because its attach has already returned.
func withTagLock(repo, parentDigest string, fn func() error) error {
	m := getTagMutex(tagMutexKey(repo, parentDigest))
	m.Lock()
	defer m.Unlock()

	return fn()
}

func FallbackTag(parentDigest string) string {
	hex, err := DigestHex(parentDigest)
	if err != nil {
		hex = strings.TrimPrefix(parentDigest, "sha256:")
		hex = strings.NewReplacer(":", "-", "/", "_", "@", "-").Replace(hex)
		return FallbackTagPrefix + hex
	}
	return FallbackTagPrefix + hex
}

// attachDescriptor publishes a descriptor in the artifact index of a parent digest.
// The caller must hold the tag lock of that digest, see withTagLock.
//
// The index is a single mutable object shared by every image resolving to that
// digest, and a registry offers neither atomic updates nor read-after-write
// guarantees, so a lost update cannot be prevented, only repaired. Attach
// therefore converges instead of writing once: it republishes the descriptor
// until it observes it in the index. Every write is a merge of what was read
// with the descriptor being attached, so concurrent writers accumulate each
// other's entries rather than truncating them.
func attachDescriptor(ctx context.Context, repo, parentDigest string, artifactDesc v1.Descriptor, artifactType, imageName string, supersededTypes []string, opts ...remote.Option) error {
	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = attachInitialInterval

	notify := func(err error, duration time.Duration) {
		logboek.Context(ctx).Warn().LogF("SBOM attach not converged yet: %s. Retrying in %v...\n", err, duration)
	}

	_, err := backoff.Retry(ctx, func() (bool, error) {
		attached, err := isAttachedInRegistry(ctx, repo, parentDigest, artifactDesc, artifactType, imageName, supersededTypes, opts...)
		if err != nil {
			return false, err
		}
		if attached {
			return true, nil
		}

		current, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
		if err != nil {
			return false, fmt.Errorf("pull fallback index: %w", err)
		}

		next := updateFallbackIndex(current, artifactDesc, artifactType, imageName, supersededTypes)
		if err := pushFallbackIndex(ctx, repo, parentDigest, next, opts...); err != nil {
			return false, fmt.Errorf("push fallback index: %w", err)
		}

		attached, err = isAttachedInRegistry(ctx, repo, parentDigest, artifactDesc, artifactType, imageName, supersededTypes, opts...)
		if err != nil {
			return false, err
		}
		if attached {
			return true, nil
		}

		return false, fmt.Errorf("attached descriptor not observed in the index yet")
	},
		backoff.WithBackOff(eb),
		backoff.WithMaxElapsedTime(attachMaxElapsedTime),
		backoff.WithNotify(notify),
	)
	if err != nil {
		return fmt.Errorf("attach artifact of type %q to digest %s: %w", artifactType, parentDigest, err)
	}

	return nil
}

func isAttachedInRegistry(ctx context.Context, repo, parentDigest string, artifactDesc v1.Descriptor, artifactType, imageName string, supersededTypes []string, opts ...remote.Option) (bool, error) {
	idx, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
	if err != nil {
		return false, fmt.Errorf("pull fallback index: %w", err)
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return false, fmt.Errorf("read fallback index manifest: %w", err)
	}

	return isAttached(im, artifactDesc, artifactType, imageName, supersededTypes), nil
}

// isAttached reports whether the index already resolves the artifact key to the
// descriptor being attached. Matching the descriptor rather than the whole index
// is what makes concurrent attaches converge: an entry added by another writer
// is a legitimate index state, not a conflict.
//
// The key is matched exactly, an empty image name included, so that it agrees
// with the replacement key of updateFallbackIndex. Reads treat an empty image
// name as a wildcard instead, which would never converge here: an artifact
// attached without an image name would keep matching the entries of named
// images and never look attached.
// The key must resolve to that descriptor and to nothing else. A stale entry of
// the same image, or the descriptor go-containerregistry adds on its own, also
// occupies the key, and both have to be evicted before the attach is done.
func isAttached(im *v1.IndexManifest, artifactDesc v1.Descriptor, artifactType, imageName string, supersededTypes []string) bool {
	occupied := 0
	for _, desc := range im.Manifests {
		for _, superseded := range supersededTypes {
			if isArtifactKey(desc, superseded, imageName) {
				return false
			}
		}
		if !isArtifactKey(desc, artifactType, imageName) {
			continue
		}
		if desc.Digest != artifactDesc.Digest {
			return false
		}
		occupied++
	}

	return occupied == 1
}

// isArtifactKey reports whether a descriptor occupies the (artifactType, imageName)
// slot of the index. Used by writers, which own exactly one slot.
func isArtifactKey(desc v1.Descriptor, artifactType, imageName string) bool {
	return desc.ArtifactType == artifactType && desc.Annotations[image.WerfImageNameAnnotation] == imageName
}

// matchDescriptors selects the entries a reader asks for. An empty image name
// means any image here, unlike the exact key used by writers.
//
// Entries are deduplicated by manifest digest: a descriptor only points at a
// manifest, so two of them sharing a digest describe one artifact. An attach
// interrupted between the artifact push and the index update leaves behind the
// descriptor go-containerregistry writes on its own, which carries no werf
// annotations and would otherwise be listed as a second, nameless artifact.
func matchDescriptors(im *v1.IndexManifest, artifactType, imageName string) []v1.Descriptor {
	position := make(map[v1.Hash]int)
	var matches []v1.Descriptor

	for _, desc := range im.Manifests {
		if desc.ArtifactType != artifactType {
			continue
		}
		if imageName != "" && desc.Annotations[image.WerfImageNameAnnotation] != imageName {
			continue
		}

		i, seen := position[desc.Digest]
		if !seen {
			position[desc.Digest] = len(matches)
			matches = append(matches, desc)
			continue
		}

		if _, annotated := matches[i].Annotations[image.WerfImageNameAnnotation]; !annotated {
			matches[i] = desc
		}
	}

	return matches
}

func GetAttached(ctx context.Context, repo, parentDigest, artifactType, imageName string, opts ...remote.Option) (v1.Descriptor, bool, error) {
	idx, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
	if err != nil {
		return v1.Descriptor{}, false, err
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return v1.Descriptor{}, false, fmt.Errorf("read fallback index manifest: %w", err)
	}

	matches := matchDescriptors(im, artifactType, imageName)
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

func PullFallbackIndex(ctx context.Context, repo, parentDigest string, opts ...remote.Option) (v1.ImageIndex, error) {
	return pullFallbackIndex(ctx, repo, parentDigest, opts...)
}

func pullFallbackIndex(ctx context.Context, repo, parentDigest string, opts ...remote.Option) (v1.ImageIndex, error) {
	tagRef, err := name.NewTag(repo + ":" + FallbackTag(parentDigest))
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

func pushFallbackIndex(ctx context.Context, repo, parentDigest string, idx v1.ImageIndex, opts ...remote.Option) error {
	tagRef, err := name.NewTag(repo + ":" + FallbackTag(parentDigest))
	if err != nil {
		return fmt.Errorf("parse fallback tag reference: %w", err)
	}

	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	if err := remote.WriteIndex(tagRef, idx, ropts...); err != nil {
		return fmt.Errorf("push fallback index: %w", err)
	}

	return nil
}

func updateFallbackIndex(current v1.ImageIndex, artifactDesc v1.Descriptor, artifactType, imageName string, supersededTypes []string) v1.ImageIndex {
	im, err := current.IndexManifest()
	if err != nil || im == nil {
		return newStaticIndex([]v1.Descriptor{artifactDesc})
	}

	kept := make([]v1.Descriptor, 0, len(im.Manifests)+1)
	for _, manifest := range im.Manifests {
		// go-containerregistry writes its own entry for the same manifest whenever the
		// pushed artifact carries a subject and the registry has no Referrers API. That
		// entry describes the manifest we are about to add, but without artifactType or
		// werf annotations, so it is matched by digest rather than by artifactType.
		if manifest.Digest == artifactDesc.Digest {
			continue
		}
		if isArtifactKey(manifest, artifactType, imageName) {
			continue
		}
		if supersededKey(manifest, supersededTypes, imageName) {
			continue
		}
		kept = append(kept, manifest)
	}
	kept = append(kept, artifactDesc)

	return newStaticIndex(kept)
}

func supersededKey(desc v1.Descriptor, supersededTypes []string, imageName string) bool {
	for _, superseded := range supersededTypes {
		if isArtifactKey(desc, superseded, imageName) {
			return true
		}
	}
	return false
}

type staticIndex struct {
	manifest *v1.IndexManifest
	raw      []byte
}

var _ v1.ImageIndex = (*staticIndex)(nil)

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
