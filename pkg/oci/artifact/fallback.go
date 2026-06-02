package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/werf/logboek"
)

const (
	FallbackTagPrefix    = "sha256-"
	EmptyConfigMediaType = "application/vnd.oci.empty.v1+json"
	maxRetries           = 3

	WerfImageNameAnnotation = "io.werf.image-name"
)

func FallbackTag(parentDigest string) string {
	hex, err := DigestHex(parentDigest)
	if err != nil {
		// Fallback to simple trim for malformed digests — this is best-effort
		return FallbackTagPrefix + parentDigest
	}
	return FallbackTagPrefix + hex
}

func Attach(ctx context.Context, repo, parentDigest string, artifactDesc v1.Descriptor, artifactType, imageName string, opts ...remote.Option) error {
	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = 500 * time.Millisecond
	eb.Reset()

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			sleepDuration := eb.NextBackOff()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepDuration):
			}
		}

		current, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
		if err != nil {
			return err
		}

		next := updateFallbackIndex(current, artifactDesc, artifactType, imageName)
		if err := pushFallbackIndex(ctx, repo, parentDigest, next, opts...); err != nil {
			return err
		}

		verified, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
		if err != nil {
			return err
		}

		verifiedDigest, err := verified.Digest()
		if err != nil {
			return fmt.Errorf("get fallback index digest: %w", err)
		}
		nextDigest, err := next.Digest()
		if err != nil {
			return fmt.Errorf("get updated index digest: %w", err)
		}

		if verifiedDigest == nextDigest {
			return nil
		}
	}

	return fmt.Errorf("attach artifact: max retries (%d) exceeded", maxRetries)
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

	var matches []v1.Descriptor
	for _, desc := range im.Manifests {
		if desc.ArtifactType != artifactType {
			continue
		}
		if imageName != "" && desc.Annotations[WerfImageNameAnnotation] != imageName {
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

func pullFallbackIndex(ctx context.Context, repo, parentDigest string, opts ...remote.Option) (v1.ImageIndex, error) {
	tagRef, err := name.NewTag(repo + ":" + FallbackTag(parentDigest))
	if err != nil {
		return nil, fmt.Errorf("parse fallback tag reference: %w", err)
	}

	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	idx, err := remote.Index(tagRef, ropts...)
	if err != nil {
		desc, getErr := remote.Get(tagRef, ropts...)
		if getErr == nil && desc != nil {
			return nil, fmt.Errorf("pull fallback index: %w", err)
		}
		return empty.Index, nil
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

func updateFallbackIndex(current v1.ImageIndex, artifactDesc v1.Descriptor, artifactType, imageName string) v1.ImageIndex {
	im, err := current.IndexManifest()
	if err != nil || im == nil {
		return newStaticIndex([]v1.Descriptor{artifactDesc})
	}

	kept := make([]v1.Descriptor, 0, len(im.Manifests)+1)
	for _, manifest := range im.Manifests {
		if manifest.ArtifactType == artifactType {
			if imageName != "" && manifest.Annotations[WerfImageNameAnnotation] == imageName {
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
