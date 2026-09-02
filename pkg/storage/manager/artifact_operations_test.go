package manager

import (
	"context"
	"errors"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/storage"
)

type artifactOperationsStorage struct {
	storage.StagesStorage
	address string

	listedParent       string
	publishedParent    string
	copiedSourceRepo   string
	copiedSourceDigest string
	copiedDestRepo     string
	copiedDestDigest   string
	resolvedProject    string
	resolvedStage      image.StageID
	resolveResult      *image.StageDesc
	operationError     error
}

func (s *artifactOperationsStorage) Address() string { return s.address }
func (s *artifactOperationsStorage) String() string  { return s.address }

func (s *artifactOperationsStorage) ListAttachedArtifacts(_ context.Context, parentDigest string) ([]v1.Descriptor, error) {
	s.listedParent = parentDigest
	return []v1.Descriptor{{Digest: v1.Hash{Algorithm: "sha256", Hex: "artifact"}}}, s.operationError
}

func (s *artifactOperationsStorage) PublishArtifact(_ context.Context, parentDigest, _ string, _ []byte, _, _, _, _ string) error {
	s.publishedParent = parentDigest
	return s.operationError
}

func (s *artifactOperationsStorage) CopyAttachedArtifacts(_ context.Context, sourceRepository, sourceDigest, destinationRepository, destinationDigest string) error {
	s.copiedSourceRepo = sourceRepository
	s.copiedSourceDigest = sourceDigest
	s.copiedDestRepo = destinationRepository
	s.copiedDestDigest = destinationDigest
	return s.operationError
}

func (s *artifactOperationsStorage) GetStageDesc(_ context.Context, projectName string, stageID image.StageID) (*image.StageDesc, error) {
	s.resolvedProject = projectName
	s.resolvedStage = stageID
	return s.resolveResult, s.operationError
}

var _ = Describe("StorageManager artifact operations", func() {
	It("routes listing, publication, resolution, and copying through the selected storages", func(ctx SpecContext) {
		source := &artifactOperationsStorage{address: "registry.example/source"}
		destination := &artifactOperationsStorage{address: "registry.example/destination"}
		stageID := image.StageID{Digest: "stage-digest", CreationTs: 42}
		resolved := &image.StageDesc{StageID: &stageID}
		destination.resolveResult = resolved
		manager := &StorageManager{ProjectName: "project"}

		artifacts, err := manager.ListAttachedArtifacts(ctx, source, "sha256:parent")
		Expect(err).NotTo(HaveOccurred())
		Expect(artifacts).To(HaveLen(1))
		Expect(source.listedParent).To(Equal("sha256:parent"))

		Expect(manager.PublishArtifact(ctx, destination, "sha256:parent", "application/test", []byte("payload"), "image", "checksum", "", "")).To(Succeed())
		Expect(destination.publishedParent).To(Equal("sha256:parent"))

		result, err := manager.ResolveStageDescriptor(ctx, destination, stageID)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(BeIdenticalTo(resolved))
		Expect(destination.resolvedProject).To(Equal("project"))
		Expect(destination.resolvedStage).To(Equal(stageID))

		Expect(manager.CopyAttachedArtifacts(ctx, source, "sha256:source", destination, "sha256:destination")).To(Succeed())
		Expect(destination.copiedSourceRepo).To(Equal(source.address))
		Expect(destination.copiedSourceDigest).To(Equal("sha256:source"))
		Expect(destination.copiedDestRepo).To(Equal(destination.address))
		Expect(destination.copiedDestDigest).To(Equal("sha256:destination"))
	})

	It("skips copying between identical repository addresses", func(ctx SpecContext) {
		source := &artifactOperationsStorage{address: "registry.example/repository"}
		destination := &artifactOperationsStorage{address: source.address}
		manager := &StorageManager{}

		Expect(manager.CopyAttachedArtifacts(ctx, source, "sha256:source", destination, "sha256:destination")).To(Succeed())
		Expect(destination.copiedSourceRepo).To(BeEmpty())
	})

	It("rejects publication and copying through local storage", func(ctx SpecContext) {
		local := storage.NewLocalStagesStorage(nil)
		manager := &StorageManager{}

		Expect(manager.PublishArtifact(ctx, local, "sha256:parent", "application/test", []byte("payload"), "image", "checksum", "", "")).To(MatchError(ContainSubstring("local stages storage")))
		Expect(manager.CopyAttachedArtifacts(ctx, local, "sha256:source", &artifactOperationsStorage{address: "registry.example/destination"}, "sha256:destination")).To(MatchError(ContainSubstring("local stages storage")))
	})

	It("wraps backend errors with the routed operation", func(ctx SpecContext) {
		backendError := errors.New("backend unavailable")
		source := &artifactOperationsStorage{address: "registry.example/source", operationError: backendError}
		manager := &StorageManager{}

		_, err := manager.ListAttachedArtifacts(ctx, source, "sha256:parent")
		Expect(err).To(MatchError(ContainSubstring("list attached artifacts from registry.example/source")))
		err = manager.PublishArtifact(ctx, source, "sha256:parent", "application/test", nil, "image", "checksum", "", "")
		Expect(err).To(MatchError(ContainSubstring("publish artifact to registry.example/source")))
	})
})
