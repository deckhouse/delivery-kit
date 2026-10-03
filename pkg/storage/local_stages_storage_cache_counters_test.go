package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/opstats"
)

func collectingContext(ctx context.Context) (context.Context, *opstats.Collector) {
	collector := opstats.NewCollector()
	return opstats.NewContext(ctx, collector), collector
}

var _ = ginkgo.Describe("Local stage lookup cache counters", func() {
	ginkgo.It("counts a lookup without the cache option as a bypass", func(specCtx ginkgo.SpecContext) {
		ctx, collector := collectingContext(specCtx)
		backend := &localImageListBackendStub{images: image.ImagesList{{RepoTags: []string{"project:" + cachedTagA}}}}

		_, err := NewLocalStagesStorage(backend).GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// The uncached lookup still refreshes the whole project snapshot, which is what the
		// locks its caller holds have to be covered by.
		gomega.Expect(backend.options.Filters).To(gomega.Equal([]util.Pair[string, string]{
			util.NewPair("reference", "project"),
		}))
		gomega.Expect(collector.CacheSummary(ctx)).To(gomega.Equal([]opstats.CacheSummary{{
			Operation: opstats.OperationDockerImageList,
			Layer:     opstats.CacheLayerMemory,
			Bypass:    1,
		}}))
	})

	ginkgo.DescribeTable("counts the first cached lookup as a miss and the next one as a hit",
		func(specCtx ginkgo.SpecContext, images image.ImagesList) {
			ctx, collector := collectingContext(specCtx)
			storage := NewLocalStagesStorage(&localImageListBackendStub{images: images})

			for range 2 {
				_, err := storage.GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}

			gomega.Expect(collector.CacheSummary(ctx)).To(gomega.Equal([]opstats.CacheSummary{{
				Operation: opstats.OperationDockerImageList,
				Layer:     opstats.CacheLayerMemory,
				Hit:       1,
				Miss:      1,
			}}))
		},
		ginkgo.Entry("a snapshot with stages", image.ImagesList{{RepoTags: []string{"project:" + cachedTagA}}}),
		// A ready snapshot answers the lookup even when the project has no images at all.
		ginkgo.Entry("an empty snapshot", image.ImagesList{}),
	)

	ginkgo.It("keeps the classification of a failed listing and counts it once", func(specCtx ginkgo.SpecContext) {
		ctx, collector := collectingContext(specCtx)
		backend := &localImageListBackendStub{err: errors.New("list failed")}

		_, err := NewLocalStagesStorage(backend).GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).To(gomega.HaveOccurred())

		gomega.Expect(collector.CacheSummary(ctx)).To(gomega.Equal([]opstats.CacheSummary{{
			Operation: opstats.OperationDockerImageList,
			Layer:     opstats.CacheLayerMemory,
			Miss:      1,
		}}))
	})

	ginkgo.It("names the row after the Buildah backend identity", func(specCtx ginkgo.SpecContext) {
		ctx, collector := collectingContext(specCtx)
		backend := &localImageListBackendStub{name: "buildah-backend"}

		_, err := NewLocalStagesStorage(backend).GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(collector.CacheSummary(ctx)).To(gomega.Equal([]opstats.CacheSummary{{
			Operation: opstats.OperationBuildahImageList,
			Layer:     opstats.CacheLayerMemory,
			Miss:      1,
		}}))
	})

	ginkgo.DescribeTable("records no row for an unrecognized backend",
		func(specCtx ginkgo.SpecContext, backendName string) {
			ctx, collector := collectingContext(specCtx)
			backend := &localImageListBackendStub{name: backendName}

			_, err := NewLocalStagesStorage(backend).GetStagesIDsByDigest(ctx, "project", cachedDigestA, 0, WithCache())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(collector.CacheSummary(ctx)).To(gomega.BeEmpty())
		},
		ginkgo.Entry("an unrelated one", "podman-backend"),
		// Only the exact identities of the known backends name a row; a docker-like name of some
		// other implementation does not make it the docker image list.
		ginkgo.Entry("a docker-like one", "docker-fancy-backend"),
	)

	ginkgo.It("counts every lookup that joined the listing in flight as a shared miss", func(specCtx ginkgo.SpecContext) {
		const joiners = 3

		ctx, collector := collectingContext(specCtx)
		backend := &localImageListBackendStub{images: image.ImagesList{{RepoTags: []string{"project:" + cachedTagA}}}}
		storage := NewLocalStagesStorage(backend)
		listing, release := blockNextListing(backend)

		registrationCtx, registered := listingRegistrations(ctx)
		done := make(chan struct{})
		var wg sync.WaitGroup
		lookup := func(lookupCtx context.Context) {
			defer wg.Done()
			defer ginkgo.GinkgoRecover()
			_, err := storage.GetStagesIDsByDigest(lookupCtx, "project", cachedDigestA, 0, WithCache())
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		wg.Add(1)
		go lookup(ctx)
		gomega.Eventually(listing).Should(gomega.BeClosed())

		// Admit the joiners only once each of them has registered with the singleflight group, so
		// that they provably joined the listing that is in flight rather than started their own.
		for range joiners {
			wg.Add(1)
			go lookup(registrationCtx)
			gomega.Eventually(registered, blockedCallTimeout).Should(gomega.Receive())
		}
		go func() {
			wg.Wait()
			close(done)
		}()

		closeIfOpen(release)
		gomega.Eventually(done, 30*time.Second).Should(gomega.BeClosed())

		// The listing ran once and answered everyone: it is a miss for all of them, and the
		// joiners, unlike the caller that started it, are shared.
		gomega.Expect(backend.callCount()).To(gomega.Equal(1))
		gomega.Expect(collector.CacheSummary(ctx)).To(gomega.Equal([]opstats.CacheSummary{{
			Operation: opstats.OperationDockerImageList,
			Layer:     opstats.CacheLayerMemory,
			Miss:      1 + joiners,
			Shared:    joiners,
		}}))
	})
})
