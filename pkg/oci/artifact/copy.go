package artifact

import (
	"context"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/image"
)

// CopyAttachedArtifacts copies every artifact attached to srcDigest in srcRepo onto
// dstDigest in dstRepo. Artifacts are re-attached from their payload rather than
// copied manifest-by-manifest, so the parent digests may differ (e.g. when a stage
// was repacked on its way to the destination). Artifacts already attached to the
// destination with the same identity (artifact type, image name, checksum, platform)
// are skipped, so the copy is idempotent. A missing source index is a no-op.
func CopyAttachedArtifacts(ctx context.Context, srcRepo, srcDigest, dstRepo, dstDigest string, opts ...remote.Option) error {
	srcOpts := opts
	dstOpts := opts
	if len(opts) == 0 {
		srcOpts = docker_registry.API().RemoteOptionsForHost(ctx, srcRepo)
		dstOpts = docker_registry.API().RemoteOptionsForHost(ctx, dstRepo)
	}

	srcIdx, err := pullFallbackIndex(ctx, srcRepo, srcDigest, srcOpts...)
	if err != nil {
		return fmt.Errorf("pull source artifact index: %w", err)
	}
	srcIM, err := srcIdx.IndexManifest()
	if err != nil {
		return fmt.Errorf("read source artifact index manifest: %w", err)
	}
	if len(srcIM.Manifests) == 0 {
		return nil
	}

	dstIdx, err := pullFallbackIndex(ctx, dstRepo, dstDigest, dstOpts...)
	if err != nil {
		return fmt.Errorf("pull destination artifact index: %w", err)
	}
	dstIM, err := dstIdx.IndexManifest()
	if err != nil {
		return fmt.Errorf("read destination artifact index manifest: %w", err)
	}

	srcStore := NewOCIStore(srcRepo, "", srcOpts...)

	for _, desc := range srcIM.Manifests {
		// Entries without an artifact type are the descriptors go-containerregistry
		// writes on its own for subject-carrying manifests; the annotated entry for
		// the same artifact is copied instead.
		if desc.ArtifactType == "" {
			continue
		}
		if hasEquivalentArtifact(dstIM, desc) {
			continue
		}

		payload, err := srcStore.GetContentByDigest(ctx, desc.Digest.String())
		if err != nil {
			return fmt.Errorf("pull artifact %s content: %w", desc.Digest.String(), err)
		}

		dstStore := NewOCIStore(dstRepo, desc.Annotations[image.WerfImageNameAnnotation], dstOpts...)
		if err := dstStore.Attach(
			ctx, dstDigest, desc.ArtifactType, payload,
			desc.Annotations[image.WerfChecksumAnnotation],
			desc.Annotations[image.WerfPlatformAnnotation],
			desc.Annotations[PredicateTypeAnnotation],
		); err != nil {
			return fmt.Errorf("attach artifact of type %q to %s: %w", desc.ArtifactType, dstRepo+"@"+dstDigest, err)
		}

		logboek.Context(ctx).Info().LogF("Copied artifact of type %q from %s to %s\n", desc.ArtifactType, srcRepo+"@"+srcDigest, dstRepo+"@"+dstDigest)
	}

	return nil
}

func hasEquivalentArtifact(dstIM *v1.IndexManifest, srcDesc v1.Descriptor) bool {
	for _, desc := range dstIM.Manifests {
		if desc.ArtifactType != srcDesc.ArtifactType {
			continue
		}
		if desc.Annotations[image.WerfImageNameAnnotation] != srcDesc.Annotations[image.WerfImageNameAnnotation] {
			continue
		}
		if desc.Annotations[image.WerfChecksumAnnotation] != srcDesc.Annotations[image.WerfChecksumAnnotation] {
			continue
		}
		if desc.Annotations[image.WerfPlatformAnnotation] != srcDesc.Annotations[image.WerfPlatformAnnotation] {
			continue
		}
		if desc.Annotations[PredicateTypeAnnotation] != srcDesc.Annotations[PredicateTypeAnnotation] {
			continue
		}
		return true
	}
	return false
}
