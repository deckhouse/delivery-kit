package storage

import (
	"errors"
	"fmt"
	"sync"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/image"
)

var (
	cachedDigestA = fmt.Sprintf("%056x", 0xaa)
	cachedDigestB = fmt.Sprintf("%056x", 0xbb)
	cachedTagA    = fmt.Sprintf("%s-%d", cachedDigestA, 1700000000001)
	cachedTagA2   = fmt.Sprintf("%s-%d", cachedDigestA, 1700000000002)
	cachedTagB    = fmt.Sprintf("%s-%d", cachedDigestB, 1700000000003)
	brokenTagA    = cachedDigestA + "-notatimestamp"
	brokenTagB    = cachedDigestB + "-notatimestamp"
)

var _ = ginkgo.Describe("Local stage lookup cache", func() {
	ginkgo.It("reuses one project image list for different missing digests", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{}
		storage := NewLocalStagesStorage(backend)

		for i := range 32 {
			stages, err := storage.GetStagesIDsByDigest(ctx, "project", fmt.Sprintf("%056x", i), 0, WithCache())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(stages).To(gomega.BeEmpty())
		}

		gomega.Expect(backend.calls).To(gomega.Equal(1))
		gomega.Expect(backend.options.Filters).To(gomega.Equal([]util.Pair[string, string]{util.NewPair("reference", "project")}))
	})

	ginkgo.DescribeTable("selects stages of the requested digest from the project snapshot",
		func(ctx ginkgo.SpecContext, images image.ImagesList, expectedTags []string) {
			backend := &localImageListBackendStub{images: images}
			stages, err := NewLocalStagesStorage(backend).GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(stageStrings(stages)).To(gomega.ConsistOf(expectedTags))
		},
		ginkgo.Entry("unlabeled stage of the project", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
		}, []string{cachedTagA}),
		ginkgo.Entry("stage labeled for another project", image.ImagesList{
			{Labels: map[string]string{image.WerfLabel: "other"}, RepoTags: []string{"project:" + cachedTagA}},
		}, []string{cachedTagA}),
		ginkgo.Entry("only matching aliases of the same image", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA, "project:" + cachedTagB, "other:" + cachedTagA2, "project:alias"}},
		}, []string{cachedTagA}),
		ginkgo.Entry("another digest is excluded", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"project:" + cachedTagB}},
		}, []string{cachedTagA}),
		ginkgo.Entry("malformed tag of another digest does not poison the lookup", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"project:" + brokenTagB}},
		}, []string{cachedTagA}),
		ginkgo.Entry("another project with the same digest is excluded", image.ImagesList{
			{RepoTags: []string{"other:" + cachedTagA}},
		}, []string{}),
		ginkgo.Entry("Buildah local reference", image.ImagesList{
			{RepoTags: []string{"localhost/project:" + cachedTagA}},
		}, []string{cachedTagA}),
		ginkgo.Entry("Buildah aliases remain scoped to project and digest", image.ImagesList{
			{RepoTags: []string{"localhost/project:" + cachedTagA, "localhost/project:" + cachedTagB, "localhost/other:" + cachedTagA2}},
		}, []string{cachedTagA}),
		ginkgo.Entry("another Buildah project is excluded", image.ImagesList{
			{RepoTags: []string{"localhost/other:" + cachedTagA}},
		}, []string{}),
		ginkgo.Entry("another registry is excluded", image.ImagesList{
			{RepoTags: []string{"registry.example/project:" + cachedTagA}},
		}, []string{}),
		ginkgo.Entry("a nested namespace is excluded", image.ImagesList{
			{RepoTags: []string{"localhost/other/project:" + cachedTagA}},
		}, []string{}),
		ginkgo.Entry("empty snapshot", image.ImagesList{}, []string{}),
	)

	ginkgo.It("preserves fresh lookup results for short Buildah references", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{
			{RepoTags: []string{"localhost/project:" + cachedTagA}},
		}}
		storage := NewLocalStagesStorage(backend)
		fresh, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(fresh)).To(gomega.ConsistOf(cachedTagA))
		cached, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(cached)).To(gomega.Equal(stageStrings(fresh)))
	})

	ginkgo.It("reports conversion errors of matching malformed tags", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{{RepoTags: []string{"project:" + brokenTagA}}}}
		_, err := NewLocalStagesStorage(backend).GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("creation timestamp")))
	})

	ginkgo.It("applies the parent timestamp filter per call, not per snapshot", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"project:" + cachedTagA2}},
		}}
		storage := NewLocalStagesStorage(backend)

		all, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(all)).To(gomega.ConsistOf(cachedTagA, cachedTagA2))

		newer, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 1700000000002, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(newer)).To(gomega.ConsistOf(cachedTagA2))

		gomega.Expect(backend.calls).To(gomega.Equal(1))
	})

	ginkgo.It("keeps other digest aliases available in the shared snapshot", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA, "project:" + cachedTagB}},
		}}
		storage := NewLocalStagesStorage(backend)
		for _, digestAndTag := range [][2]string{{cachedDigestA, cachedTagA}, {cachedDigestB, cachedTagB}} {
			stages, err := storage.GetStagesIDsByDigest(ctx, "project", digestAndTag[0], 0, WithCache())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(stageStrings(stages)).To(gomega.ConsistOf(digestAndTag[1]))
		}
		gomega.Expect(backend.calls).To(gomega.Equal(1))
	})

	ginkgo.It("keeps a separate snapshot per project", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"other:" + cachedTagA2}},
		}}
		storage := NewLocalStagesStorage(backend)

		first, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(first)).To(gomega.ConsistOf(cachedTagA))

		second, err := storage.GetStagesIDsByDigest(ctx, "other", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(second)).To(gomega.ConsistOf(cachedTagA2))

		gomega.Expect(backend.calls).To(gomega.Equal(2))
		gomega.Expect(backend.options.Filters).To(gomega.Equal([]util.Pair[string, string]{util.NewPair("reference", "other")}))
	})

	ginkgo.It("does not cache failed listings", func(ctx ginkgo.SpecContext) {
		listErr := errors.New("list failed")
		backend := &localImageListBackendStub{err: listErr}
		storage := NewLocalStagesStorage(backend)

		_, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).To(gomega.MatchError(listErr))

		backend.err = nil
		backend.images = image.ImagesList{{RepoTags: []string{"project:" + cachedTagA}}}
		stages, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(stages)).To(gomega.ConsistOf(cachedTagA))
		gomega.Expect(backend.calls).To(gomega.Equal(2))
	})

	ginkgo.It("lists images fresh and filtered by digest without the cache option", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{{RepoTags: []string{"project:" + cachedTagA}}}}
		storage := NewLocalStagesStorage(backend)

		cached, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(cached)).To(gomega.ConsistOf(cachedTagA))

		backend.images = image.ImagesList{{RepoTags: []string{"project:" + cachedTagA, "project:" + cachedTagA2}}}

		fresh, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(fresh)).To(gomega.ConsistOf(cachedTagA, cachedTagA2))
		gomega.Expect(backend.options.Filters).To(gomega.Equal([]util.Pair[string, string]{util.NewPair("reference", "project:"+cachedDigestA+"*")}))
		gomega.Expect(backend.calls).To(gomega.Equal(2))
	})

	ginkgo.It("lists the project once for concurrent lookups of different digests", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"project:" + cachedTagB}},
		}}
		storage := NewLocalStagesStorage(backend)

		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, digestAndTag := range [][2]string{{cachedDigestA, cachedTagA}, {cachedDigestB, cachedTagB}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stages, err := storage.GetStagesIDsByDigest(ctx, "project", digestAndTag[0], 0, WithCache())
				if err != nil {
					results <- err
					return
				}
				if len(stages) != 1 || stages[0].String() != digestAndTag[1] {
					results <- fmt.Errorf("unexpected stages %v for digest %s", stageStrings(stages), digestAndTag[0])
					return
				}
				results <- nil
			}()
		}
		wg.Wait()
		close(results)

		for err := range results {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
		gomega.Expect(backend.calls).To(gomega.Equal(1))
	})
})

var _ = ginkgo.Describe("Local stage lookup cache maintenance", func() {
	warmSnapshot := image.ImagesList{{RepoTags: []string{"project:" + cachedTagA, "project:" + cachedTagB}}}

	warmedStorage := func(ctx ginkgo.SpecContext, backend container_backend.ContainerBackend) *LocalStagesStorage {
		storage := NewLocalStagesStorage(backend)
		stages, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(stages)).To(gomega.ConsistOf(cachedTagA))
		return storage
	}

	cachedStages := func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, digest string) []string {
		stages, err := storage.GetStagesIDsByDigest(ctx, "project", digest, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		return stageStrings(stages)
	}

	ginkgo.DescribeTable("refreshes the cached tags of the listed digest only",
		func(ctx ginkgo.SpecContext, freshListing image.ImagesList, expectedA, expectedB []string) {
			backend := &localImageListBackendStub{images: warmSnapshot}
			storage := warmedStorage(ctx, backend)

			backend.images = freshListing
			_, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.ConsistOf(expectedA))
			gomega.Expect(cachedStages(ctx, storage, cachedDigestB)).To(gomega.ConsistOf(expectedB))
			gomega.Expect(backend.calls).To(gomega.Equal(2))
		},
		ginkgo.Entry("a new tag of the digest becomes visible", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"project:" + cachedTagA2}},
		}, []string{cachedTagA, cachedTagA2}, []string{cachedTagB}),
		ginkgo.Entry("a replaced tag of the digest drops the old one", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA2}},
		}, []string{cachedTagA2}, []string{cachedTagB}),
		ginkgo.Entry("an empty listing clears the digest only", image.ImagesList{},
			[]string{}, []string{cachedTagB}),
		ginkgo.Entry("an alias of another digest is not duplicated", image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA2, "project:" + cachedTagB}},
		}, []string{cachedTagA2}, []string{cachedTagB}),
		ginkgo.Entry("a Buildah reference refreshes the same digest", image.ImagesList{
			{RepoTags: []string{"localhost/project:" + cachedTagA2}},
		}, []string{cachedTagA2}, []string{cachedTagB}),
	)

	ginkgo.It("keeps the cached tags when a fresh listing fails", func(ctx ginkgo.SpecContext) {
		listErr := errors.New("list failed")
		backend := &localImageListBackendStub{images: warmSnapshot}
		storage := warmedStorage(ctx, backend)

		backend.images, backend.err = nil, listErr
		_, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0)
		gomega.Expect(err).To(gomega.MatchError(listErr))

		backend.err = nil
		gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.ConsistOf(cachedTagA))
	})

	ginkgo.It("does not initialize the snapshot from a digest-filtered listing", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: image.ImagesList{{RepoTags: []string{"project:" + cachedTagA}}}}
		storage := NewLocalStagesStorage(backend)

		fresh, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(fresh)).To(gomega.ConsistOf(cachedTagA))

		backend.images = warmSnapshot
		gomega.Expect(cachedStages(ctx, storage, cachedDigestB)).To(gomega.ConsistOf(cachedTagB))
		gomega.Expect(backend.calls).To(gomega.Equal(2))
		gomega.Expect(backend.options.Filters).To(gomega.Equal([]util.Pair[string, string]{util.NewPair("reference", "project")}))
	})

	ginkgo.It("caches the fresh listing before the parent timestamp filter", func(ctx ginkgo.SpecContext) {
		backend := &localImageListBackendStub{images: warmSnapshot}
		storage := warmedStorage(ctx, backend)

		backend.images = image.ImagesList{
			{RepoTags: []string{"project:" + cachedTagA}},
			{RepoTags: []string{"project:" + cachedTagA2}},
		}
		filtered, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 1700000000002)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(stageStrings(filtered)).To(gomega.ConsistOf(cachedTagA2))

		gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.ConsistOf(cachedTagA, cachedTagA2))
	})

	ginkgo.DescribeTable("makes a stage published by this process visible to cached lookups",
		func(ctx ginkgo.SpecContext, publish func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, backend *localPublishBackendStub) error, expectedTags []string) {
			backend := newLocalPublishBackendStub(image.ImagesList{{RepoTags: []string{"project:" + cachedTagB}}})
			storage := NewLocalStagesStorage(backend)
			gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.BeEmpty())

			err := publish(ctx, storage, backend)
			if len(expectedTags) == 0 {
				gomega.Expect(err).To(gomega.HaveOccurred())
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}

			gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.ConsistOf(expectedTags))
			gomega.Expect(cachedStages(ctx, storage, cachedDigestB)).To(gomega.ConsistOf(cachedTagB))
			gomega.Expect(backend.calls).To(gomega.Equal(1))
		},
		ginkgo.Entry("a tagged stage image", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, _ *localPublishBackendStub) error {
			return storage.StoreImage(ctx, &localStageImageStub{name: "project:" + cachedTagA})
		}, []string{cachedTagA}),
		ginkgo.Entry("a stage image that could not be tagged", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, backend *localPublishBackendStub) error {
			backend.tagImageErr = errors.New("tag failed")
			return storage.StoreImage(ctx, &localStageImageStub{name: "project:" + cachedTagA})
		}, nil),
		ginkgo.Entry("a natively mutated stage image", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, _ *localPublishBackendStub) error {
			return storage.MutateAndPushImage(ctx, "project:"+cachedTagB, "project:"+cachedTagA, image.SpecConfig{}, &localStageImageStub{name: "project:" + cachedTagB})
		}, []string{cachedTagA}),
		ginkgo.Entry("a stage image mutated through the save/load fallback", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, backend *localPublishBackendStub) error {
			backend.nativeErr = container_backend.ErrNativeMutationUnsupported
			return storage.MutateAndPushImage(ctx, "project:"+cachedTagB, "project:"+cachedTagA, image.SpecConfig{}, &localStageImageStub{name: "project:" + cachedTagB})
		}, []string{cachedTagA}),
		ginkgo.Entry("a stage image whose native mutation failed", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, backend *localPublishBackendStub) error {
			backend.nativeErr = errors.New("mutation failed")
			return storage.MutateAndPushImage(ctx, "project:"+cachedTagB, "project:"+cachedTagA, image.SpecConfig{}, &localStageImageStub{name: "project:" + cachedTagB})
		}, nil),
		ginkgo.Entry("a stage image whose fallback tag failed", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, backend *localPublishBackendStub) error {
			backend.nativeErr = container_backend.ErrNativeMutationUnsupported
			backend.tagErr = errors.New("tag failed")
			return storage.MutateAndPushImage(ctx, "project:"+cachedTagB, "project:"+cachedTagA, image.SpecConfig{}, &localStageImageStub{name: "project:" + cachedTagB})
		}, nil),
		ginkgo.Entry("a Buildah stage image", func(ctx ginkgo.SpecContext, storage *LocalStagesStorage, _ *localPublishBackendStub) error {
			return storage.StoreImage(ctx, &localStageImageStub{name: "localhost/project:" + cachedTagA})
		}, []string{cachedTagA}),
	)

	ginkgo.DescribeTable("does not lose a stage published while a listing is in flight", func(ctx ginkgo.SpecContext, fresh bool) {
		listing, release, tagging := make(chan struct{}), make(chan struct{}), make(chan struct{})
		backend := newLocalPublishBackendStub(nil)
		storage := NewLocalStagesStorage(backend)
		if fresh {
			gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.BeEmpty())
		}
		backend.onList = func() {
			close(listing)
			<-release
		}
		backend.onTag = func() { close(tagging) }
		ginkgo.DeferCleanup(func() {
			select {
			case <-release:
			default:
				close(release)
			}
		})

		lookup := make(chan []string, 1)
		go func() {
			defer ginkgo.GinkgoRecover()
			var opts []Option
			if !fresh {
				opts = append(opts, WithCache())
			}
			stages, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, opts...)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			lookup <- stageStrings(stages)
		}()
		<-listing

		stored := make(chan error, 1)
		go func() {
			defer ginkgo.GinkgoRecover()
			stored <- storage.StoreImage(ctx, &localStageImageStub{name: "project:" + cachedTagA})
		}()
		<-tagging
		gomega.Consistently(stored).ShouldNot(gomega.Receive())
		close(release)

		gomega.Expect(<-stored).To(gomega.Succeed())
		gomega.Expect(<-lookup).To(gomega.BeEmpty())
		gomega.Expect(cachedStages(ctx, storage, cachedDigestA)).To(gomega.ConsistOf(cachedTagA))
		expectedCalls := 1
		if fresh {
			expectedCalls++
		}
		gomega.Expect(backend.calls).To(gomega.Equal(expectedCalls))
	},
		ginkgo.Entry("project warm-up", false),
		ginkgo.Entry("digest refresh", true),
	)
})
