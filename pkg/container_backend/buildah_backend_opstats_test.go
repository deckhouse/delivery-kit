package container_backend

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/opstats"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/pkg/buildahstub"
)

var _ = ginkgo.Describe("BuildahBackend operation stats", func() {
	var (
		collector *opstats.Collector
		ctx       context.Context
	)

	ginkgo.BeforeEach(func() {
		collector = opstats.NewCollector()
		ctx = opstats.NewContext(context.Background(), collector)
	})

	ginkgo.It("does not measure the Dockerfile build preparation", func() {
		gomega.Expect(werf.Init(ginkgo.GinkgoT().TempDir(), "")).To(gomega.Succeed())

		var atBuild []opstats.OperationSummary
		stub := &dockerfileBuildStub{onBuild: func(_ context.Context) {
			atBuild = collector.Summary()
		}}
		backend := NewBuildahBackend(stub, BuildahBackendOptions{})

		imageID, err := backend.BuildDockerfile(ctx, []byte("FROM scratch\n"), BuildDockerfileOpts{
			BuildContextArchive: &stubBuildContextArchive{dir: ginkgo.GinkgoT().TempDir()},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(imageID).To(gomega.Equal("sha256:built"))

		gomega.Expect(atBuild).To(gomega.BeEmpty(), "the preparation of the build context is a werf-level step and must not be measured")
		gomega.Expect(collector.Summary()).To(gomega.BeEmpty())
	})

	ginkgo.It("does not aggregate the whole Stapel stage build", func() {
		stub := &buildahstub.BuildahStub{}
		backend := NewBuildahBackend(stub, BuildahBackendOptions{})

		_, err := backend.BuildStapelStage(ctx, "base-image", BuildStapelStageOptions{})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(collector.Summary()).To(gomega.BeEmpty())
	})

	ginkgo.It("serializes concurrent pulls of the same image", func() {
		backend := NewBuildahBackend(&buildahstub.BuildahStub{}, BuildahBackendOptions{})

		unlock := backend.lockPull("image")
		waiterDone := make(chan struct{})
		go func() {
			defer close(waiterDone)
			backend.lockPull("image")()
		}()
		gomega.Consistently(waiterDone, 100*time.Millisecond).ShouldNot(gomega.BeClosed())
		unlock()
		gomega.Eventually(waiterDone).Should(gomega.BeClosed())

		gomega.Expect(collector.Summary()).To(gomega.BeEmpty(), "the pull lock wait is a werf-level wait and must not be measured")
	})

	ginkgo.It("unpacks data archives into the container root", func() {
		container := &containerDesc{Name: "container", RootMount: ginkgo.GinkgoT().TempDir()}

		err := (&BuildahBackend{}).applyDataArchives(ctx, container, []DataArchiveSpec{
			{Archive: newTarArchive("file.txt", "content"), Type: DirectoryArchive, To: "/app"},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(os.ReadFile(filepath.Join(container.RootMount, "app", "file.txt"))).To(gomega.Equal([]byte("content")))

		gomega.Expect(collector.Summary()).To(gomega.BeEmpty(), "unpacking files is a werf-level step and must not be measured")
	})

	ginkgo.It("removes data from the container root", func() {
		rootMount := ginkgo.GinkgoT().TempDir()
		removedPath := filepath.Join(rootMount, "app", "file.txt")
		gomega.Expect(os.MkdirAll(filepath.Dir(removedPath), 0o755)).To(gomega.Succeed())
		gomega.Expect(os.WriteFile(removedPath, []byte("content"), 0o644)).To(gomega.Succeed())

		err := (&BuildahBackend{}).applyRemoveData(ctx, &containerDesc{Name: "container", RootMount: rootMount}, []RemoveDataSpec{
			{Type: RemoveExactPath, Paths: []string{"/app/file.txt"}},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(removedPath).ToNot(gomega.BeAnExistingFile())

		gomega.Expect(collector.Summary()).To(gomega.BeEmpty(), "removing files is a werf-level step and must not be measured")
	})
})
