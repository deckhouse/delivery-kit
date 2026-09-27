package storage

import (
	"errors"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = ginkgo.Describe("stage lookup", func() {
	ginkgo.DescribeTable("returns an unavailable error instead of a nil descriptor",
		func(ctx ginkgo.SpecContext, present, rejected bool, expected error) {
			registry := &stageLookupRegistry{markerRegistry: newMarkerRegistry()}
			storage := &RepoStagesStorage{RepoAddress: "registry.example/project", DockerRegistry: registry}
			stageID := image.NewStageID("digest", 1)
			if present {
				registry.put(storage.ConstructStageImageName("project", stageID.Digest, stageID.CreationTs), nil)
			}
			if rejected {
				registry.put(makeRepoRejectedStageImageRecord(storage.RepoAddress, stageID.Digest, stageID.CreationTs), nil)
			}

			desc, err := storage.GetStageDesc(ctx, "project", *stageID)
			if expected != nil {
				gomega.Expect(err).To(gomega.MatchError(expected))
				gomega.Expect(IsErrStageUnavailable(err)).To(gomega.BeTrue())
				gomega.Expect(desc).To(gomega.BeNil())
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(desc).NotTo(gomega.BeNil())
				gomega.Expect(desc.StageID).To(gomega.Equal(stageID))
			}
		},
		ginkgo.Entry("missing", false, false, ErrStageNotFound),
		ginkgo.Entry("rejected", true, true, ErrStageRejected),
		ginkgo.Entry("available", true, false, nil),
	)

	ginkgo.It("returns an unavailable error for a missing local image", func(ctx ginkgo.SpecContext) {
		storage := NewLocalStagesStorage(&stageLookupBackend{})
		desc, err := storage.GetStageDesc(ctx, "project", *image.NewStageID("digest", 1))
		gomega.Expect(err).To(gomega.MatchError(ErrStageNotFound))
		gomega.Expect(desc).To(gomega.BeNil())
	})

	ginkgo.It("replaces a destination whose manifest references missing blobs", func(ctx ginkgo.SpecContext) {
		host := startLocalRegistry(ctx)
		registry := &stageLookupRegistry{markerRegistry: newMarkerRegistry()}
		source := &RepoStagesStorage{RepoAddress: host + "/source", DockerRegistry: registry}
		destination := &RepoStagesStorage{RepoAddress: host + "/destination", DockerRegistry: registry}
		stageID := image.NewStageID("digest", 1)
		sourceRef := source.ConstructStageImageName("project", stageID.Digest, stageID.CreationTs)
		destinationRef := destination.ConstructStageImageName("project", stageID.Digest, stageID.CreationTs)
		registry.put(sourceRef, nil)
		registry.put(destinationRef, nil)
		registry.brokenImage = registry.images[destinationRef]

		desc, err := destination.CopyFromStorage(ctx, source, "project", *stageID, CopyFromStorageOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(desc).NotTo(gomega.BeNil())
		gomega.Expect(desc.Info.Name).To(gomega.Equal(destinationRef))
		gomega.Expect(desc.Info).NotTo(gomega.BeIdenticalTo(registry.brokenImage))
	})

	ginkgo.DescribeTable("copies a missing destination without hiding other failures",
		func(ctx ginkgo.SpecContext, existing, rejected bool, copyErr, expected error) {
			host := startLocalRegistry(ctx)
			registry := &stageLookupRegistry{markerRegistry: newMarkerRegistry()}
			registry.copyErr = copyErr
			source := &RepoStagesStorage{RepoAddress: host + "/source", DockerRegistry: registry}
			destination := &RepoStagesStorage{RepoAddress: host + "/destination", DockerRegistry: registry}
			stageID := image.NewStageID("digest", 1)
			sourceRef := source.ConstructStageImageName("project", stageID.Digest, stageID.CreationTs)
			destinationRef := destination.ConstructStageImageName("project", stageID.Digest, stageID.CreationTs)
			registry.put(sourceRef, nil)
			if existing {
				registry.put(destinationRef, nil)
			}
			if rejected {
				registry.put(makeRepoRejectedStageImageRecord(destination.RepoAddress, stageID.Digest, stageID.CreationTs), nil)
			}

			desc, err := destination.CopyFromStorage(ctx, source, "project", *stageID, CopyFromStorageOptions{})
			if expected != nil {
				gomega.Expect(errors.Is(err, expected)).To(gomega.BeTrue(), "error: %v", err)
				gomega.Expect(desc).To(gomega.BeNil())
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(desc).NotTo(gomega.BeNil())
				gomega.Expect(desc.Info.Name).To(gomega.Equal(destinationRef))
			}
		},
		ginkgo.Entry("copy on miss", false, false, nil, nil),
		ginkgo.Entry("reuse an existing image without copying", true, false, ErrBrokenImage, nil),
		ginkgo.Entry("preserve a rejection", true, true, nil, ErrStageRejected),
		ginkgo.Entry("propagate a copy error", false, false, ErrBrokenImage, ErrBrokenImage),
	)

	ginkgo.It("copies artifacts attached to the copied stage", func(ctx ginkgo.SpecContext) {
		const artifactType = "application/vnd.dsse.envelope.v1+json"

		host := startLocalRegistry(ctx)
		registry := &stageLookupRegistry{markerRegistry: newMarkerRegistry(), realCopy: true}
		source := &RepoStagesStorage{RepoAddress: host + "/source", DockerRegistry: registry}
		destination := &RepoStagesStorage{RepoAddress: host + "/destination", DockerRegistry: registry}
		stageID := image.NewStageID("digest", 1)
		sourceRef := source.ConstructStageImageName("project", stageID.Digest, stageID.CreationTs)

		img, err := random.Image(256, 1)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ref, err := name.NewTag(sourceRef)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Write(ref, img, remote.WithContext(ctx))).To(gomega.Succeed())
		sourceDigest, err := img.Digest()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		putWithDigest(registry.markerRegistry, sourceRef, source.RepoAddress+"@"+sourceDigest.String())

		store := artifact.NewOCIStore(source.RepoAddress, "app")
		gomega.Expect(store.Attach(ctx, sourceDigest.String(), artifactType, []byte(`{"v":1}`), "checksum-v1", "linux/amd64", "")).To(gomega.Succeed())

		desc, err := destination.CopyFromStorage(ctx, source, "project", *stageID, CopyFromStorageOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(desc).NotTo(gomega.BeNil())

		_, found, err := artifact.NewOCIStore(destination.RepoAddress, "app").GetAttached(ctx, desc.Info.GetDigest(), artifactType, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeTrue())
	})
})
