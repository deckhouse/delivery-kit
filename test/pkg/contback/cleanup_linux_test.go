package contback

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"go.podman.io/common/libimage"
	"go.podman.io/storage"
)

var _ = ginkgo.Describe("Buildah cleanup inventory", func() {
	var store storage.Store
	var imageRuntime *libimage.Runtime
	var inventoryStore *cleanupInventoryStore
	var lookupStore *cleanupLookupStore
	const project = "werf-test-inventory"

	ginkgo.BeforeEach(func() {
		dir := ginkgo.GinkgoT().TempDir()
		var err error
		store, err = storage.GetStore(storage.StoreOptions{
			RunRoot: filepath.Join(dir, "run"), GraphRoot: filepath.Join(dir, "graph"), GraphDriverName: "vfs",
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ginkgo.DeferCleanup(func() {
			_, err := store.Shutdown(false)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		inventoryStore = &cleanupInventoryStore{Store: store}
		imageRuntime, err = libimage.RuntimeFromStore(inventoryStore, &libimage.RuntimeOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		lookupStore = &cleanupLookupStore{Store: store}
	})

	ginkgo.It("traces storage lookup, untag and deletion during real cleanup", func() {
		ownedID := createCleanupImage(store, project, "owned", []string{"localhost/" + project + ":owned"})
		aliasedID := createCleanupImage(store, project, "aliased", []string{"localhost/" + project + ":aliased", "localhost/foreign:keep"})
		var output bytes.Buffer
		traced := &cleanupTraceStore{Store: store, writer: &output, projectName: project}
		runtime, err := libimage.RuntimeFromStore(traced, &libimage.RuntimeOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		request := cleanupProjectRequest{ProjectName: project, ImageIDs: []string{ownedID, aliasedID}}
		gomega.Expect(cleanupBuildahProjectImages(context.Background(), request, traced, runtime)).To(gomega.Succeed())
		for _, operation := range []string{"Image", "ImageBigData", "ListImageBigData", "ImageBigDataSize", "LayersByUncompressedDigest", "MultiList", "RemoveNames", "DeleteImage"} {
			gomega.Expect(output.String()).To(gomega.MatchRegexp(`storage\.` + operation + ` call=\d+.*event=start`))
			expectedError := `<nil>`
			if operation == "LayersByUncompressedDigest" {
				expectedError = `.*layer not known`
			}
			gomega.Expect(output.String()).To(gomega.MatchRegexp(`storage\.` + operation + ` call=\d+.*event=done elapsed=\S+ error=` + expectedError))
		}
		gomega.Expect(output.String()).To(gomega.ContainSubstring(`commit=true`))
		gomega.Expect(output.String()).NotTo(gomega.ContainSubstring(`"rootfs"`))
		_, err = store.Image(ownedID)
		gomega.Expect(errors.Is(err, storage.ErrImageUnknown)).To(gomega.BeTrue())
		remaining, err := store.Image(aliasedID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remaining.Names).To(gomega.Equal([]string{"localhost/foreign:keep"}))
	})

	ginkgo.It("cleans journal IDs without listing and still checks ownership", func() {
		ownedID := createCleanupImage(store, project, "owned", []string{"localhost/" + project + ":owned"})
		aliasedID := createCleanupImage(store, project, "aliased", []string{"localhost/" + project + ":aliased", "localhost/foreign:keep"})
		danglingID := createCleanupImage(store, project, "dangling", nil)
		foreignID := createCleanupImage(store, "werf-test-other", "foreign", []string{"localhost/" + project + ":foreign"})
		request := cleanupProjectRequest{ProjectName: project, ImageIDs: []string{ownedID, aliasedID, danglingID, foreignID, strings.Repeat("f", 64)}}
		gomega.Expect(cleanupBuildahProjectImages(context.Background(), request, store, imageRuntime)).To(gomega.Succeed())
		gomega.Expect(inventoryStore.listings).To(gomega.BeZero())
		for _, id := range []string{ownedID, danglingID} {
			_, err := store.Image(id)
			gomega.Expect(errors.Is(err, storage.ErrImageUnknown)).To(gomega.BeTrue())
		}
		image, err := store.Image(aliasedID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(image.Names).To(gomega.Equal([]string{"localhost/foreign:keep"}))
		_, err = store.Image(foreignID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cleanupBuildahProjectImages(context.Background(), cleanupProjectRequest{ProjectName: project, ImageIDs: []string{}}, store, imageRuntime)).To(gomega.Succeed())
		gomega.Expect(inventoryStore.listings).To(gomega.BeZero())
	})

	ginkgo.It("refreshes only discovered IDs and preserves foreign aliases and ownership", func() {
		ownedID := createCleanupImage(store, project, "owned", []string{"localhost/" + project + ":owned"})
		aliasedID := createCleanupImage(store, project, "aliased", []string{"localhost/" + project + ":aliased", "localhost/foreign:keep"})
		danglingID := createCleanupImage(store, project, "dangling", nil)
		foreignID := createCleanupImage(store, "werf-test-other", "foreign", []string{"localhost/" + project + ":foreign"})
		for index := 0; index < 32; index++ {
			createCleanupImage(store, "werf-test-other", fmt.Sprintf("unrelated-%d", index), []string{fmt.Sprintf("localhost/other:%d", index)})
		}
		gomega.Expect(cleanupBuildahProjectImages(context.Background(), cleanupProjectRequest{ProjectName: project}, lookupStore, imageRuntime)).To(gomega.Succeed())
		gomega.Expect(inventoryStore.listings).To(gomega.Equal(1))
		gomega.Expect(lookupStore.lookups).To(gomega.ConsistOf(ownedID, aliasedID, danglingID))
		for _, id := range []string{ownedID, danglingID} {
			_, err := store.Image(id)
			gomega.Expect(errors.Is(err, storage.ErrImageUnknown)).To(gomega.BeTrue())
		}
		image, err := store.Image(aliasedID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(image.Names).To(gomega.Equal([]string{"localhost/foreign:keep"}))
		_, err = store.Image(foreignID)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.DescribeTable("removes newly exposed references on an already discovered ID", func(kind string) {
		imageID := createCleanupImage(store, project, "aliased", []string{"localhost/" + project + ":owned", "localhost/foreign:keep"})
		lookupStore.beforeLookup = func() error {
			if kind == "tagless" {
				return store.SetNames(imageID, nil)
			}
			name := "localhost/" + project + ":remaining"
			if kind == "digest" {
				image, err := store.Image(imageID)
				if err != nil {
					return err
				}
				name = "localhost/" + project + "@" + image.Digest.String()
			}
			return store.SetNames(imageID, []string{name, "localhost/foreign:keep"})
		}
		gomega.Expect(cleanupBuildahProjectImages(context.Background(), cleanupProjectRequest{ProjectName: project}, lookupStore, imageRuntime)).To(gomega.Succeed())
		gomega.Expect(inventoryStore.listings).To(gomega.Equal(1))
		gomega.Expect(lookupStore.lookups).To(gomega.Equal([]string{imageID, imageID}))
		image, err := store.Image(imageID)
		if kind == "tagless" {
			gomega.Expect(errors.Is(err, storage.ErrImageUnknown)).To(gomega.BeTrue())
			return
		}
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(image.Names).To(gomega.Equal([]string{"localhost/foreign:keep"}))
	}, ginkgo.Entry("tag", "tag"), ginkgo.Entry("digest alias", "digest"), ginkgo.Entry("tagless", "tagless"))

	ginkgo.It("propagates refresh failures instead of accepting an empty inventory", func() {
		createCleanupImage(store, project, "owned", []string{"localhost/" + project + ":owned"})
		lookupStore.lookupError = errors.New("storage unavailable")
		err := cleanupBuildahProjectImages(context.Background(), cleanupProjectRequest{ProjectName: project}, lookupStore, imageRuntime)
		gomega.Expect(errors.Is(err, lookupStore.lookupError)).To(gomega.BeTrue())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("verify buildah test image cleanup")))
	})
})

var _ = ginkgo.Describe("Buildah cleanup trace", func() {
	ginkgo.It("logs storage start before delegation and preserves results and errors", func() {
		var output bytes.Buffer
		expectedErr := fmt.Errorf("busy image: %w", storage.ErrImageUsedByContainer)
		underlying := &cleanupDeleteStore{deleteImage: func(id string, commit bool) ([]string, error) {
			gomega.Expect(id).To(gomega.Equal("image-id"))
			gomega.Expect(commit).To(gomega.BeFalse())
			gomega.Expect(output.String()).To(gomega.ContainSubstring(`storage.DeleteImage call=1`))
			gomega.Expect(output.String()).To(gomega.ContainSubstring("event=start"))
			gomega.Expect(output.String()).NotTo(gomega.ContainSubstring("event=done"))
			return []string{"layer-id"}, expectedErr
		}}
		traced := &cleanupTraceStore{Store: underlying, writer: &output, projectName: "werf-test-trace"}
		layers, err := traced.DeleteImage("image-id", false)
		gomega.Expect(layers).To(gomega.Equal([]string{"layer-id"}))
		gomega.Expect(err).To(gomega.BeIdenticalTo(expectedErr))
		gomega.Expect(output.String()).To(gomega.MatchRegexp(`storage\.DeleteImage call=1.*event=done elapsed=\S+ error=busy image:`))
	})

	ginkgo.It("reports phase start immediately and records elapsed time and errors", func() {
		var output bytes.Buffer
		done := traceBuildahCleanupPhase(&output, "werf-test-trace", "open storage")
		gomega.Expect(output.String()).To(gomega.ContainSubstring(`project="werf-test-trace"`))
		gomega.Expect(output.String()).To(gomega.ContainSubstring(`phase="open storage" event=start`))
		gomega.Expect(output.String()).NotTo(gomega.ContainSubstring("event=done"))
		done(errors.New("storage unavailable"))
		gomega.Expect(output.String()).To(gomega.MatchRegexp(`phase="open storage" event=done elapsed=\S+ error=storage unavailable`))
	})

	ginkgo.It("streams worker output before cancellation and retains it in the failure", func() {
		if os.Geteuid() == 0 {
			ginkgo.Skip("requires non-root execution to exercise the buildah unshare command")
		}
		dir := ginkgo.GinkgoT().TempDir()
		const marker = "cleanup-worker-started"
		script := "#!/bin/sh\nprintf 'cleanup-worker-started\\n' >&2\nkill -STOP $$\n"
		gomega.Expect(os.WriteFile(filepath.Join(dir, "buildah"), []byte(script), 0o700)).To(gomega.Succeed())
		ginkgo.GinkgoT().Setenv("PATH", dir)
		observer := &cleanupTraceObserver{marker: marker, started: make(chan struct{})}
		ginkgo.GinkgoWriter.TeeTo(observer)
		defer ginkgo.GinkgoWriter.ClearTeeWriters()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- cleanupBuildahProject(ctx, "werf-test-trace", nil)
		}()
		streamed := false
		select {
		case <-observer.started:
			streamed = true
			cancel()
		case <-ctx.Done():
		}
		err := <-result
		gomega.Expect(streamed).To(gomega.BeTrue(), "worker output must arrive before the process exits")
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring(marker))
		gomega.Expect(observer.output.String()).To(gomega.ContainSubstring(`phase="worker process" event=done`))
	})
})
