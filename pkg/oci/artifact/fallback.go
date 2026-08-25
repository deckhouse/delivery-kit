package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// PredicateTypeAnnotation is the cosign-convention annotation carrying the in-toto
// predicate type of an attestation artifact. It is written both into the artifact
// manifest and its fallback-index descriptor, and is part of the slot identity:
// artifacts of different predicate kinds (e.g. SBOM and VEX) sharing one artifact
// type occupy distinct slots. Entries without the annotation predate this scheme
// and are treated as legacy candidates whose kind is only known from their content.
const PredicateTypeAnnotation = "dev.sigstore.bundle.predicateType"

// Key identifies a superseded artifact slot: the artifact type together with the
// predicate type recorded in PredicateTypeAnnotation (empty for legacy entries).
type Key struct {
	ArtifactType  string
	PredicateType string
}

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
func attachDescriptor(ctx context.Context, repo, parentDigest string, artifactDesc v1.Descriptor, artifactType, imageName, predicateType string, superseded []Key, opts ...remote.Option) error {
	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = attachInitialInterval

	notify := func(err error, duration time.Duration) {
		logboek.Context(ctx).Warn().LogF("Artifact attach not converged yet: %s. Retrying in %v...\n", err, duration)
	}

	_, err := backoff.Retry(ctx, func() (bool, error) {
		attached, err := isAttachedInRegistry(ctx, repo, parentDigest, artifactDesc, artifactType, imageName, predicateType, superseded, opts...)
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

		next := updateFallbackIndex(current, artifactDesc, artifactType, imageName, predicateType, superseded)
		if err := pushFallbackIndex(ctx, repo, parentDigest, next, opts...); err != nil {
			return false, fmt.Errorf("push fallback index: %w", err)
		}

		attached, err = isAttachedInRegistry(ctx, repo, parentDigest, artifactDesc, artifactType, imageName, predicateType, superseded, opts...)
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

func isAttachedInRegistry(ctx context.Context, repo, parentDigest string, artifactDesc v1.Descriptor, artifactType, imageName, predicateType string, superseded []Key, opts ...remote.Option) (bool, error) {
	idx, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
	if err != nil {
		return false, fmt.Errorf("pull fallback index: %w", err)
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return false, fmt.Errorf("read fallback index manifest: %w", err)
	}

	return isAttached(im, artifactDesc, artifactType, imageName, predicateType, superseded), nil
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
func isAttached(im *v1.IndexManifest, artifactDesc v1.Descriptor, artifactType, imageName, predicateType string, superseded []Key) bool {
	occupied := 0
	for _, desc := range im.Manifests {
		if supersededKey(desc, superseded, imageName) {
			return false
		}
		if !isArtifactKey(desc, artifactType, imageName, predicateType) {
			continue
		}
		if desc.Digest != artifactDesc.Digest {
			return false
		}
		occupied++
	}

	return occupied == 1
}

// isArtifactKey reports whether a descriptor occupies the (artifactType, imageName,
// predicateType) slot of the index. Used by writers, which own exactly one slot.
// A descriptor without the predicate annotation occupies the legacy ("") predicate slot.
func isArtifactKey(desc v1.Descriptor, artifactType, imageName, predicateType string) bool {
	return desc.ArtifactType == artifactType &&
		desc.Annotations[image.WerfImageNameAnnotation] == imageName &&
		desc.Annotations[PredicateTypeAnnotation] == predicateType
}

// matchDescriptors selects the entries a reader asks for. An empty image name
// means any image here, unlike the exact key used by writers.
//
// Entries annotated with one of the requested predicate types come first; entries
// without the predicate annotation are legacy candidates appended last — their kind
// is only known from their content, so callers must verify it before use. Entries
// annotated with a different predicate type are excluded. An empty predicateTypes
// set matches any entry.
//
// Entries are deduplicated by manifest digest: a descriptor only points at a
// manifest, so two of them sharing a digest describe one artifact. An attach
// interrupted between the artifact push and the index update leaves behind the
// descriptor go-containerregistry writes on its own, which carries no werf
// annotations and would otherwise be listed as a second, nameless artifact.
func matchDescriptors(im *v1.IndexManifest, artifactType, imageName string, predicateTypes []string) []v1.Descriptor {
	seen := make(map[v1.Hash]bool)
	var annotated []v1.Descriptor

	for _, desc := range im.Manifests {
		if !matchesReaderFilter(desc, artifactType, imageName) {
			continue
		}
		predicate, hasPredicate := desc.Annotations[PredicateTypeAnnotation]
		if !hasPredicate {
			continue
		}
		if len(predicateTypes) > 0 && !slices.Contains(predicateTypes, predicate) {
			continue
		}
		if seen[desc.Digest] {
			continue
		}
		seen[desc.Digest] = true
		annotated = append(annotated, desc)
	}

	position := make(map[v1.Hash]int)
	var legacy []v1.Descriptor

	for _, desc := range im.Manifests {
		if !matchesReaderFilter(desc, artifactType, imageName) {
			continue
		}
		if _, hasPredicate := desc.Annotations[PredicateTypeAnnotation]; hasPredicate {
			continue
		}
		if seen[desc.Digest] {
			continue
		}

		i, met := position[desc.Digest]
		if !met {
			position[desc.Digest] = len(legacy)
			legacy = append(legacy, desc)
			continue
		}

		if _, named := legacy[i].Annotations[image.WerfImageNameAnnotation]; !named {
			legacy[i] = desc
		}
	}

	return append(annotated, legacy...)
}

func matchesReaderFilter(desc v1.Descriptor, artifactType, imageName string) bool {
	if desc.ArtifactType != artifactType {
		return false
	}
	return imageName == "" || desc.Annotations[image.WerfImageNameAnnotation] == imageName
}

func GetAttached(ctx context.Context, repo, parentDigest, artifactType, imageName string, predicateTypes []string, opts ...remote.Option) (v1.Descriptor, bool, error) {
	idx, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
	if err != nil {
		return v1.Descriptor{}, false, err
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return v1.Descriptor{}, false, fmt.Errorf("read fallback index manifest: %w", err)
	}

	matches := matchDescriptors(im, artifactType, imageName, predicateTypes)
	if len(matches) == 0 {
		return v1.Descriptor{}, false, nil
	}

	if imageName == "" && len(matches) > 1 {
		logboek.Context(ctx).Warn().LogF("%s", multipleArtifactEntriesWarning(parentDigest, matches))
	}

	return matches[0], true, nil
}

func multipleArtifactEntriesWarning(parentDigest string, matches []v1.Descriptor) string {
	names := make([]string, 0, len(matches))
	for _, desc := range matches {
		entryName := desc.Annotations[image.WerfImageNameAnnotation]
		if entryName == "" {
			entryName = "<unnamed>"
		}
		names = append(names, entryName)
	}
	return fmt.Sprintf("WARNING: multiple artifact entries for digest %q (imageName not specified in lookup): entries carry image names [%s]; selected entry with image name %q\n",
		parentDigest, strings.Join(names, ", "), names[0])
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

func updateFallbackIndex(current v1.ImageIndex, artifactDesc v1.Descriptor, artifactType, imageName, predicateType string, superseded []Key) v1.ImageIndex {
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
		if isArtifactKey(manifest, artifactType, imageName, predicateType) {
			continue
		}
		if supersededKey(manifest, superseded, imageName) {
			continue
		}
		kept = append(kept, manifest)
	}
	kept = append(kept, artifactDesc)

	return newStaticIndex(kept)
}

func supersededKey(desc v1.Descriptor, superseded []Key, imageName string) bool {
	for _, key := range superseded {
		if isArtifactKey(desc, key.ArtifactType, imageName, key.PredicateType) {
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
