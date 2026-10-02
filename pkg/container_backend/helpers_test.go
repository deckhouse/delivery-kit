package container_backend

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/buildah"
	"github.com/werf/werf/v3/pkg/docker"
	"github.com/werf/werf/v3/pkg/opstats"
)

var _ BuildContextArchiver = (*stubBuildContextArchive)(nil)

type stubBuildContextArchive struct {
	BuildContextArchiver
	dir string
}

func (a *stubBuildContextArchive) ExtractOrGetExtractedDir(_ context.Context) (string, error) {
	return a.dir, nil
}

var _ buildah.Buildah = (*dockerfileBuildStub)(nil)

type dockerfileBuildStub struct {
	buildah.Buildah
	onBuild func(ctx context.Context)
}

func (b *dockerfileBuildStub) BuildFromDockerfile(ctx context.Context, _ string, _ buildah.BuildFromDockerfileOpts) (string, error) {
	if b.onBuild != nil {
		b.onBuild(ctx)
	}
	return "sha256:built", nil
}

func newTarArchive(name, content string) io.ReadCloser {
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	gomega.Expect(writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))})).To(gomega.Succeed())
	_, err := writer.Write([]byte(content))
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	return io.NopCloser(&buf)
}

// dockerDaemonContext points the docker client at a fake daemon serving handler and returns
// a context carrying both that client and a fresh operation collector.
func dockerDaemonContext(handler http.Handler) (context.Context, *opstats.Collector) {
	server := httptest.NewServer(handler)
	ginkgo.DeferCleanup(server.Close)
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"} {
		ginkgo.GinkgoT().Setenv(key, "")
	}
	ginkgo.GinkgoT().Setenv("DOCKER_HOST", "tcp://"+server.Listener.Addr().String())

	ctx, err := docker.NewContextWithStreams(context.Background(), io.Discard, io.Discard)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	collector := opstats.NewCollector()
	return opstats.NewContext(ctx, collector), collector
}

func daemonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.47")
			w.Header().Set("OSType", "linux")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, err := io.WriteString(w, body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
}

func operationCount(collector *opstats.Collector, op opstats.Operation) int {
	for _, summary := range collector.Summary() {
		if summary.Operation == op {
			return summary.Count
		}
	}
	return 0
}
