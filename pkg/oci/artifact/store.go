package artifact

import (
	"context"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type Store interface {
	Attach(ctx context.Context, parentDigest, artifactType string, payload []byte, checksum string) error
	GetAttachedContent(ctx context.Context, parentDigest, artifactType string) ([]byte, error)
	GetAttached(ctx context.Context, parentDigest, artifactType string) (v1.Descriptor, bool, error)
}

type OCIStore struct {
	repo      string
	imageName string
}

func NewOCIStore(repo, imageName string) *OCIStore {
	return &OCIStore{
		repo:      repo,
		imageName: imageName,
	}
}

func (s *OCIStore) Attach(ctx context.Context, parentDigest, artifactType string, payload []byte, checksum string) error {
	layer := static.NewLayer(payload, types.MediaType(artifactType))
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return fmt.Errorf("append artifact layer: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(EmptyConfigMediaType))

	parentRef, err := name.NewDigest(s.repo + "@" + parentDigest)
	if err != nil {
		return fmt.Errorf("parse parent digest reference: %w", err)
	}
	parentDesc, err := remote.Get(parentRef, s.remoteOptions(ctx)...)
	if err != nil {
		return fmt.Errorf("get parent descriptor: %w", err)
	}
	imgWithSubject := mutate.Subject(img, parentDesc.Descriptor).(v1.Image)
	imgWithSubject = mutate.ConfigMediaType(imgWithSubject, types.MediaType(artifactType))

	if err := PushArtifactImage(ctx, s.repo, imgWithSubject); err != nil {
		return err
	}

	desc, err := partial.Descriptor(imgWithSubject)
	if err != nil {
		return fmt.Errorf("create descriptor: %w", err)
	}
	artifactDesc := *desc
	artifactDesc.ArtifactType = artifactType

	annotations := make(map[string]string)
	if checksum != "" {
		annotations["io.werf.checksum"] = checksum
	}
	if s.imageName != "" {
		annotations[WerfImageNameAnnotation] = s.imageName
	}
	if len(annotations) > 0 {
		artifactDesc.Annotations = annotations
	}

	return Attach(ctx, s.repo, parentDigest, artifactDesc, artifactType, s.imageName)
}

func (s *OCIStore) GetAttached(ctx context.Context, parentDigest, artifactType string) (v1.Descriptor, bool, error) {
	return GetAttached(ctx, s.repo, parentDigest, artifactType, s.imageName)
}

func (s *OCIStore) GetAttachedContent(ctx context.Context, parentDigest, artifactType string) ([]byte, error) {
	desc, found, err := s.GetAttached(ctx, parentDigest, artifactType)
	if err != nil {
		return nil, fmt.Errorf("get attached artifact: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no artifact of type %q found for digest %q: %w", artifactType, parentDigest, ErrNotFound)
	}

	imageRef, err := name.NewDigest(s.repo + "@" + desc.Digest.String())
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

	rc, err := layers[0].Compressed()
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
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
}
