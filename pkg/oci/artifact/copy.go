package artifact

import (
	"context"
	"errors"
	"fmt"
	"slices"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
)

// SupersedeRule reports the destination slots the artifact occupying the copied
// slot replaces, given the slots the source holds for the same image. It lets a
// copy evict what the source has evicted, which the artifact store cannot decide
// on its own: slot kinship is a property of the attestation kinds layered above
// it.
type SupersedeRule func(copied Key, srcSlots []Key) []Key

// CopyAllAttachedArtifacts copies every artifact attached to srcDigest in srcRepo
// onto dstDigest in dstRepo, and when srcDigest is an image index it also copies
// the artifacts attached to every manifest the index references. Referenced
// manifests are addressed by the same digest in both repositories, which holds for
// registry-level copies — the only in-scope way an index travels between
// repositories.
func CopyAllAttachedArtifacts(ctx context.Context, srcRepo, srcDigest, dstRepo, dstDigest string, supersede SupersedeRule, opts ...remote.Option) error {
	if err := CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, dstDigest, supersede, opts...); err != nil {
		return err
	}

	referenced, err := listReferencedDigests(ctx, srcRepo, srcDigest, opts...)
	if err != nil {
		// A source that does not hold the manifest holds no artifacts attached to it
		// either, which is the same no-op CopyAttachedArtifacts makes of a missing
		// fallback index rather than a reason to fail the operation that copied the
		// image.
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == 404 {
			return nil
		}
		return fmt.Errorf("list index manifests of %s: %w", srcRepo+"@"+srcDigest, err)
	}

	for _, digest := range referenced {
		if err := CopyAttachedArtifacts(ctx, srcRepo, digest, dstRepo, digest, supersede, opts...); err != nil {
			return fmt.Errorf("copy artifacts of index manifest %s: %w", digest, err)
		}
	}

	return nil
}

// CopyAttachedArtifacts copies every artifact attached to srcDigest in srcRepo onto
// dstDigest in dstRepo. Artifacts are re-attached from their payload rather than
// copied manifest-by-manifest, so the parent digests may differ (e.g. when a stage
// was repacked on its way to the destination). Artifacts already attached to the
// destination with the same identity (artifact type, image name, checksum, platform)
// are skipped unless they leave a slot the source no longer holds behind, so the
// copy is idempotent and still converges on the slot state of the source. The
// source is the source of truth: the copy carries no notion of recency, so a
// destination entry the rule reports as superseded is evicted even when it is the
// fresher of the two — but only when werf produced it: an attestation published
// through werf attest sign carries no checksum annotation and cannot be produced
// again, so it survives a copy into its slot. A missing source index is a no-op.
func CopyAttachedArtifacts(ctx context.Context, srcRepo, srcDigest, dstRepo, dstDigest string, supersede SupersedeRule, opts ...remote.Option) error {
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

		imageName := desc.Annotations[image.WerfImageNameAnnotation]
		evictable := evictableSlots(dstIM, imageName)
		superseded := lo.Filter(supersede(descriptorSlot(desc), imageSlots(srcIM, imageName)), func(key Key, _ int) bool {
			return slices.Contains(evictable, key)
		})

		if len(superseded) == 0 && hasEquivalentArtifact(dstIM, desc) {
			continue
		}

		payload, err := srcStore.GetContentByDigest(ctx, desc.Digest.String())
		if err != nil {
			return fmt.Errorf("pull artifact %s content: %w", desc.Digest.String(), err)
		}

		dstStore := NewOCIStore(dstRepo, imageName, dstOpts...)
		if err := dstStore.AttachSuperseding(
			ctx, dstDigest, desc.ArtifactType, payload,
			desc.Annotations[image.WerfChecksumAnnotation],
			desc.Annotations[image.WerfPlatformAnnotation],
			desc.Annotations[PredicateTypeAnnotation],
			superseded,
		); err != nil {
			return fmt.Errorf("attach artifact of type %q to %s: %w", desc.ArtifactType, dstRepo+"@"+dstDigest, err)
		}

		logboek.Context(ctx).Info().LogF("Copied artifact of type %q from %s to %s\n", desc.ArtifactType, srcRepo+"@"+srcDigest, dstRepo+"@"+dstDigest)
	}

	return nil
}

func descriptorSlot(desc v1.Descriptor) Key {
	return Key{ArtifactType: desc.ArtifactType, PredicateType: desc.Annotations[PredicateTypeAnnotation]}
}

func imageSlots(im *v1.IndexManifest, imageName string) []Key {
	var slots []Key
	for _, desc := range im.Manifests {
		if desc.ArtifactType == "" || desc.Annotations[image.WerfImageNameAnnotation] != imageName {
			continue
		}
		slots = append(slots, descriptorSlot(desc))
	}
	return slots
}

func evictableSlots(im *v1.IndexManifest, imageName string) []Key {
	var slots []Key
	for _, desc := range im.Manifests {
		if desc.ArtifactType == "" || desc.Annotations[image.WerfImageNameAnnotation] != imageName {
			continue
		}
		if desc.Annotations[image.WerfChecksumAnnotation] == "" {
			continue
		}
		slots = append(slots, descriptorSlot(desc))
	}
	return slots
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
