package container_backend

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/buildah"
	"github.com/werf/werf/v3/pkg/opstats"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/pkg/buildahstub"
)

type stubBuildContextArchive struct {
	BuildContextArchiver
	dir string
}

func (a *stubBuildContextArchive) ExtractOrGetExtractedDir(_ context.Context) (string, error) {
	return a.dir, nil
}

type slowDockerfileBuildStub struct {
	buildah.Buildah
	duration time.Duration
}

func (b *slowDockerfileBuildStub) BuildFromDockerfile(_ context.Context, _ string, _ buildah.BuildFromDockerfileOpts) (string, error) {
	time.Sleep(b.duration)
	return "sha256:built", nil
}

func newTarArchive(name, content string) io.ReadCloser {
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	Expect(writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))})).To(Succeed())
	_, err := writer.Write([]byte(content))
	Expect(err).ToNot(HaveOccurred())
	Expect(writer.Close()).To(Succeed())
	return io.NopCloser(&buf)
}

var _ = Describe("BuildahBackend operation stats", func() {
	var (
		collector *opstats.Collector
		ctx       context.Context
	)

	BeforeEach(func() {
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

	It("measures only the build context preparation around the Dockerfile build", func() {
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())

		backend := NewBuildahBackend(&slowDockerfileBuildStub{duration: 200 * time.Millisecond}, BuildahBackendOptions{})

		imageID, err := backend.BuildDockerfile(ctx, []byte("FROM scratch\n"), BuildDockerfileOpts{
			BuildContextArchive: &stubBuildContextArchive{dir: GinkgoT().TempDir()},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(imageID).To(Equal("sha256:built"))

		prepare := observed("buildah: stage prepare")
		Expect(prepare).ToNot(BeNil())
		Expect(prepare.Count).To(Equal(1))
		Expect(prepare.TotalTime).To(BeNumerically("<", 100*time.Millisecond))
		Expect(observed(opstats.OperationStageBuild)).To(BeNil())
	})

	It("does not aggregate the whole Stapel stage build", func() {
		stub := &buildahstub.BuildahStub{}
		backend := NewBuildahBackend(stub, BuildahBackendOptions{})

		_, err := backend.BuildStapelStage(ctx, "base-image", BuildStapelStageOptions{})
		Expect(err).ToNot(HaveOccurred())
		Expect(collector.Summary()).To(BeEmpty())
	})

	It("measures unpacking data archives into the container root", func() {
		container := &containerDesc{Name: "container", RootMount: GinkgoT().TempDir()}

		err := (&BuildahBackend{}).applyDataArchives(ctx, container, []DataArchiveSpec{
			{Archive: newTarArchive("file.txt", "content"), Type: DirectoryArchive, To: "/app"},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(os.ReadFile(filepath.Join(container.RootMount, "app", "file.txt"))).To(Equal([]byte("content")))

		unpack := observed("buildah: unpack files")
		Expect(unpack).ToNot(BeNil())
		Expect(unpack.Count).To(Equal(1))
	})

	It("measures removing data from the container root", func() {
		rootMount := GinkgoT().TempDir()
		removedPath := filepath.Join(rootMount, "app", "file.txt")
		Expect(os.MkdirAll(filepath.Dir(removedPath), 0o755)).To(Succeed())
		Expect(os.WriteFile(removedPath, []byte("content"), 0o644)).To(Succeed())

		err := (&BuildahBackend{}).applyRemoveData(ctx, &containerDesc{Name: "container", RootMount: rootMount}, []RemoveDataSpec{
			{Type: RemoveExactPath, Paths: []string{"/app/file.txt"}},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(removedPath).ToNot(BeAnExistingFile())

		remove := observed("buildah: remove files")
		Expect(remove).ToNot(BeNil())
		Expect(remove.Count).To(Equal(1))
	})
})
