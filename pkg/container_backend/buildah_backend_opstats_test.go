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

	observed := func(op opstats.Operation) *opstats.OperationSummary {
		for _, s := range collector.Summary() {
			if s.Operation == op {
				return &s
			}
		}
		return nil
	}

	ginkgo.It("closes the build context preparation before the Dockerfile build starts", func() {
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

		gomega.Expect(atBuild).To(gomega.HaveLen(1), "the preparation must be recorded, and nothing else, by the time the build starts")
		gomega.Expect(atBuild[0].Operation).To(gomega.Equal(opstats.Operation("buildah: stage prepare")))
		gomega.Expect(atBuild[0].Count).To(gomega.Equal(1))

		gomega.Expect(observed("buildah: stage prepare").Count).To(gomega.Equal(1), "the deferred call must not record the preparation a second time")
		gomega.Expect(observed(opstats.OperationStageBuild)).To(gomega.BeNil())
	})

	ginkgo.It("does not aggregate the whole Stapel stage build", func() {
		stub := &buildahstub.BuildahStub{}
		backend := NewBuildahBackend(stub, BuildahBackendOptions{})

		_, err := backend.BuildStapelStage(ctx, "base-image", BuildStapelStageOptions{})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(collector.Summary()).To(gomega.BeEmpty())
	})

	ginkgo.It("measures waiting for a concurrent pull of the same image", func() {
		backend := NewBuildahBackend(&buildahstub.BuildahStub{}, BuildahBackendOptions{})

		unlock := backend.lockPull(ctx, "image")
		waiterDone := make(chan struct{})
		go func() {
			defer close(waiterDone)
			backend.lockPull(ctx, "image")()
		}()
		gomega.Consistently(waiterDone, 100*time.Millisecond).ShouldNot(gomega.BeClosed())
		unlock()
		gomega.Eventually(waiterDone).Should(gomega.BeClosed())

		wait := observed("buildah: image pull lock wait")
		gomega.Expect(wait).ToNot(gomega.BeNil())
		gomega.Expect(wait.Count).To(gomega.Equal(2))
		gomega.Expect(wait.MaxTime).To(gomega.BeNumerically(">=", 100*time.Millisecond))
	})

	ginkgo.It("measures unpacking data archives into the container root", func() {
		container := &containerDesc{Name: "container", RootMount: ginkgo.GinkgoT().TempDir()}

		err := (&BuildahBackend{}).applyDataArchives(ctx, container, []DataArchiveSpec{
			{Archive: newTarArchive("file.txt", "content"), Type: DirectoryArchive, To: "/app"},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(os.ReadFile(filepath.Join(container.RootMount, "app", "file.txt"))).To(gomega.Equal([]byte("content")))

		unpack := observed("buildah: unpack files")
		gomega.Expect(unpack).ToNot(gomega.BeNil())
		gomega.Expect(unpack.Count).To(gomega.Equal(1))
	})

	ginkgo.It("measures removing data from the container root", func() {
		rootMount := ginkgo.GinkgoT().TempDir()
		removedPath := filepath.Join(rootMount, "app", "file.txt")
		gomega.Expect(os.MkdirAll(filepath.Dir(removedPath), 0o755)).To(gomega.Succeed())
		gomega.Expect(os.WriteFile(removedPath, []byte("content"), 0o644)).To(gomega.Succeed())

		err := (&BuildahBackend{}).applyRemoveData(ctx, &containerDesc{Name: "container", RootMount: rootMount}, []RemoveDataSpec{
			{Type: RemoveExactPath, Paths: []string{"/app/file.txt"}},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(removedPath).ToNot(gomega.BeAnExistingFile())

		remove := observed("buildah: remove files")
		gomega.Expect(remove).ToNot(gomega.BeNil())
		gomega.Expect(remove.Count).To(gomega.Equal(1))
	})
})
