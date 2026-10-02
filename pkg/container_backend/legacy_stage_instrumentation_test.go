package container_backend

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/docker"
	"github.com/werf/werf/v3/pkg/opstats"
)

var _ = Describe("Legacy stage container instrumentation", func() {
	It("records the stage preparation separately from the container run", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/_ping") {
				w.Header().Set("API-Version", "1.47")
				w.Header().Set("OSType", "linux")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, err := io.WriteString(w, `{"message":"daemon failure"}`)
			Expect(err).NotTo(HaveOccurred())
		}))
		DeferCleanup(server.Close)
		for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"} {
			GinkgoT().Setenv(key, "")
		}
		GinkgoT().Setenv("DOCKER_HOST", "tcp://"+server.Listener.Addr().String())

		ctx, err := docker.NewContextWithStreams(context.Background(), io.Discard, io.Discard)
		Expect(err).NotTo(HaveOccurred())

		collector := opstats.NewCollector()
		ctx = opstats.NewContext(ctx, collector)

		backend := &DockerServerBackend{}
		image := &LegacyStageImage{
			legacyBaseImage: newLegacyBaseImage("stage", backend),
			targetPlatform:  "linux/amd64",
			fromImage: &LegacyStageImage{
				legacyBaseImage: newLegacyBaseImage("base", backend),
			},
		}
		container := newLegacyStageImageContainer(image)

		Expect(container.run(ctx)).NotTo(Succeed())

		Expect(operationCount(collector, "docker: stage prepare")).To(Equal(1))
		Expect(operationCount(collector, "docker: image inspect")).To(Equal(1))
		Expect(operationCount(collector, "docker: container run")).To(Equal(0), "the run must not be measured when the preparation fails")
	})
})

func operationCount(collector *opstats.Collector, op opstats.Operation) int {
	for _, summary := range collector.Summary() {
		if summary.Operation == op {
			return summary.Count
		}
	}
	return 0
}
