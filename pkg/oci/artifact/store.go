package artifact

import (
	"context"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/image"
)

type Store interface {
	Attach(ctx context.Context, parentDigest, artifactType string, payload []byte, checksum, targetPlatform string) error
	GetAttachedContent(ctx context.Context, parentDigest, artifactType string) ([]byte, error)
	GetAttachedContentAny(ctx context.Context, parentDigest, artifactType string) ([]byte, error)
	GetAttached(ctx context.Context, parentDigest, artifactType string) (v1.Descriptor, bool, error)
}

// OCIStore manages OCI artifacts attached to container images.
// An artifact is an OCI image with a subject reference pointing to the parent image digest.
type OCIStore struct {
	repo      string
	imageName string
	opts      []remote.Option
}

var _ Store = (*OCIStore)(nil)

// NewOCIStore creates a new OCIStore for the given repository and optional image name.
// By default, registry authentication is handled via the global docker_registry API.
// Explicit remote options can be passed to override the default auth, though in most
// cases the default werf registry authentication should suffice.
func NewOCIStore(repo, imageName string, opts ...remote.Option) *OCIStore {
	return &OCIStore{
		repo:      repo,
		imageName: imageName,
		opts:      opts,
	}
}

func (s *OCIStore) Attach(ctx context.Context, parentDigest, artifactType string, payload []byte, checksum, targetPlatform string) error {
	return s.AttachSuperseding(ctx, parentDigest, artifactType, payload, checksum, targetPlatform, nil)
}

// AttachSuperseding attaches the artifact like Attach and additionally removes
// index entries of the superseded artifact types for the same image name, so a
// format migration leaves a single artifact behind.
func (s *OCIStore) AttachSuperseding(ctx context.Context, parentDigest, artifactType string, payload []byte, checksum, targetPlatform string, supersededTypes []string) error {
	annotations := s.artifactAnnotations(checksum, targetPlatform)

	img, err := buildArtifactImage(payload, artifactType, annotations)
	if err != nil {
		return err
	}

	parentRef, err := name.NewDigest(s.repo + "@" + parentDigest)
	if err != nil {
		return fmt.Errorf("parse parent digest reference: %w", err)
	}
	parentDesc, err := remote.Get(parentRef, s.remoteOptions(ctx)...)
	if err != nil {
		return fmt.Errorf("get parent descriptor: %w", err)
	}
	imgWithSubject := mutate.Subject(img, parentDesc.Descriptor).(v1.Image)

	return withTagLock(s.repo, parentDigest, func() error {
		if err := PushArtifactImage(ctx, s.repo, imgWithSubject, s.remoteOptions(ctx)...); err != nil {
			return err
		}

		desc, err := partial.Descriptor(imgWithSubject)
		if err != nil {
			return fmt.Errorf("create descriptor: %w", err)
		}
		artifactDesc := *desc
		artifactDesc.ArtifactType = artifactType
		if len(annotations) > 0 {
			artifactDesc.Annotations = annotations
		}

		return attachDescriptor(ctx, s.repo, parentDigest, artifactDesc, artifactType, s.imageName, supersededTypes, s.remoteOptions(ctx)...)
	})
}

// buildArtifactImage assembles the artifact image carrying the payload as its single layer.
//
// The artifact type is declared through the config media type: go-containerregistry v0.20.1
// cannot emit the OCI 1.1 manifest-level artifactType field, and per the OCI spec a registry
// falls back to config.mediaType when artifactType is absent. Annotations go into the
// manifest so that a Referrers API response carries them once a registry starts indexing
// artifacts by subject.
func buildArtifactImage(payload []byte, artifactType string, annotations map[string]string) (v1.Image, error) {
	layer := static.NewLayer(payload, types.MediaType(artifactType))

	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return nil, fmt.Errorf("append artifact layer: %w", err)
	}

	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(artifactType))

	if len(annotations) > 0 {
		img = mutate.Annotations(img, annotations).(v1.Image)
	}

	return img, nil
}

// artifactAnnotations builds the werf annotations identifying an artifact. They are
// written both into the artifact manifest and into its descriptor in the fallback index:
// the manifest copy is what a registry reports through the Referrers API, the descriptor
// copy is what the fallback index lookup filters on.
func (s *OCIStore) artifactAnnotations(checksum, targetPlatform string) map[string]string {
	annotations := make(map[string]string)
	if checksum != "" {
		annotations[image.WerfChecksumAnnotation] = checksum
	}
	if s.imageName != "" {
		annotations[image.WerfImageNameAnnotation] = s.imageName
	}
	if targetPlatform != "" {
		annotations[image.WerfPlatformAnnotation] = targetPlatform
	}
	return annotations
}

// GetAttached returns the descriptor of an artifact attached to the given parent image digest.
//
// Two parent images with the same digest share the same attached artifact: if image A
// at digest D has an SBOM attached, any image with digest D (same content) shares that SBOM.
// The artifact is identified by the (parentDigest, artifactType, imageName) tuple.
func (s *OCIStore) GetAttached(ctx context.Context, parentDigest, artifactType string) (v1.Descriptor, bool, error) {
	return GetAttached(ctx, s.repo, parentDigest, artifactType, s.imageName, s.remoteOptions(ctx)...)
}

func (s *OCIStore) GetAttachedContent(ctx context.Context, parentDigest, artifactType string) ([]byte, error) {
	desc, found, err := s.GetAttached(ctx, parentDigest, artifactType)
	if err != nil {
		return nil, fmt.Errorf("get attached artifact: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no artifact of type %q found for digest %q: %w", artifactType, parentDigest, ErrNotFound)
	}

	return s.pullLayerContent(ctx, desc.Digest.String())
}

// GetAttachedContentAny returns the content of the first matching artifact
// attached to the given parent digest, regardless of image name. If multiple
// artifacts of the same type exist (e.g., different images sharing the same
// parent digest), the first match is returned and a warning is logged.
// Callers needing a specific artifact should use GetAttachedContent with an
// imageName-configured store instead.
func (s *OCIStore) GetAttachedContentAny(ctx context.Context, parentDigest, artifactType string) ([]byte, error) {
	desc, found, err := GetAttached(ctx, s.repo, parentDigest, artifactType, "", s.remoteOptions(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("get attached artifact: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no artifact of type %q found for digest %q: %w", artifactType, parentDigest, ErrNotFound)
	}

	return s.pullLayerContent(ctx, desc.Digest.String())
}

// GetContentByDigest returns the content of the artifact image identified by the
// exact digest. Use this when the descriptor is already known (e.g. iterating the
// fallback index), instead of re-resolving by (parentDigest, artifactType).
func (s *OCIStore) GetContentByDigest(ctx context.Context, digest string) ([]byte, error) {
	return s.pullLayerContent(ctx, digest)
}

func (s *OCIStore) pullLayerContent(ctx context.Context, digest string) ([]byte, error) {
	imageRef, err := name.NewDigest(s.repo + "@" + digest)
	if err != nil {
		return nil, fmt.Errorf("parse artifact digest reference: %w", err)
	}

	img, err := remote.Image(imageRef, s.remoteOptions(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("pull artifact image: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("get artifact layers: %w", err)
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("artifact has no layers")
	}

	payload, err := readLayerContent(layers[0])
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func readLayerContent(layer v1.Layer) ([]byte, error) {
	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("read artifact layer: %w", err)
	}
	defer rc.Close()

	payload, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read artifact content: %w", err)
	}

	return payload, nil
}

func (s *OCIStore) remoteOptions(ctx context.Context) []remote.Option {
	opts := s.opts
	if len(opts) == 0 {
		opts = docker_registry.API().RemoteOptionsForHost(ctx, s.repo)
	}
	return append([]remote.Option{remote.WithContext(ctx)}, opts...)
}
