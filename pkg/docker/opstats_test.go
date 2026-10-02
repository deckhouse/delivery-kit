package docker

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/opstats"
)

func observedDaemonContext(handler http.HandlerFunc) (context.Context, *opstats.Collector) {
	collector := opstats.NewCollector()
	return opstats.NewContext(daemonSettingsContext(handler), collector), collector
}

func respondJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.47")
			w.Header().Set("OSType", "linux")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, body); err != nil {
			panic(err)
		}
	}
}

func respondError(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/_ping") {
		w.Header().Set("API-Version", "1.47")
		w.Header().Set("OSType", "linux")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	if _, err := io.WriteString(w, `{"message":"daemon failure"}`); err != nil {
		panic(err)
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

var _ = DescribeTable("docker api operations", func(ctx SpecContext, label opstats.Operation, handler http.HandlerFunc, call func(ctx context.Context) error, expectError bool) {
	apiCtx, collector := observedDaemonContext(handler)

	err := call(apiCtx)
	if expectError {
		Expect(err).To(HaveOccurred())
	} else {
		Expect(err).NotTo(HaveOccurred())
	}

	Expect(collector.Summary()).To(HaveLen(1), "exactly one operation must be recorded")
	Expect(operationCount(collector, label)).To(Equal(1))
},
	Entry("image list", opstats.Operation("docker: image list"), respondJSON(`[]`), func(ctx context.Context) error {
		_, err := Images(ctx, client.ImageListOptions{})
		return err
	}, false),
	Entry("image list failure", opstats.Operation("docker: image list"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := Images(ctx, client.ImageListOptions{})
		return err
	}, true),
	Entry("image inspect", opstats.Operation("docker: image inspect"), respondJSON(`{"Id":"sha256:abc"}`), func(ctx context.Context) error {
		_, err := ImageInspect(ctx, "img")
		return err
	}, false),
	Entry("image inspect failure", opstats.Operation("docker: image inspect"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := ImageInspect(ctx, "img")
		return err
	}, true),
	Entry("container list", opstats.Operation("docker: container list"), respondJSON(`[]`), func(ctx context.Context) error {
		_, err := Containers(ctx, client.ContainerListOptions{})
		return err
	}, false),
	Entry("container inspect", opstats.Operation("docker: container inspect"), respondJSON(`{"Id":"c"}`), func(ctx context.Context) error {
		_, err := ContainerInspect(ctx, "c")
		return err
	}, false),
	Entry("container commit", opstats.Operation("docker: container commit"), respondJSON(`{"Id":"sha256:abc"}`), func(ctx context.Context) error {
		_, err := ContainerCommit(ctx, "c", client.ContainerCommitOptions{})
		return err
	}, false),
	Entry("container commit failure", opstats.Operation("docker: container commit"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := ContainerCommit(ctx, "c", client.ContainerCommitOptions{})
		return err
	}, true),
	Entry("container remove", opstats.Operation("docker: container remove"), respondJSON(``), func(ctx context.Context) error {
		return ContainerRemove(ctx, "c", client.ContainerRemoveOptions{})
	}, false),
	Entry("image prune", opstats.Operation("docker: image prune"), respondJSON(`{"ImagesDeleted":[],"SpaceReclaimed":0}`), func(ctx context.Context) error {
		_, err := ImagesPrune(ctx, ImagesPruneOptions{})
		return err
	}, false),
	Entry("image load", opstats.Operation("docker: image load"), respondJSON(`{"stream":"Loaded image ID: sha256:abc"}`), func(ctx context.Context) error {
		_, err := CliLoadFromStream(ctx, strings.NewReader(""))
		return err
	}, false),
)

var _ = Describe("docker container create", func() {
	It("records a single container create", func(ctx SpecContext) {
		apiCtx, collector := observedDaemonContext(respondJSON(`{"Id":"c"}`))

		id, err := ContainerCreate(apiCtx, &dockercontainer.Config{Image: "img"}, nil, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(id).To(Equal("c"))

		Expect(collector.Summary()).To(HaveLen(1))
		Expect(operationCount(collector, "docker: container create")).To(Equal(1))
	})
})

var _ = DescribeTable("docker stream operations", func(ctx SpecContext, label opstats.Operation, open func(ctx context.Context) (io.ReadCloser, error)) {
	apiCtx, collector := observedDaemonContext(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.47")
			w.Header().Set("OSType", "linux")
			return
		}
		w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString([]byte(`{"name":"src","size":14,"mode":420,"mtime":"2020-01-01T00:00:00Z"}`)))
		w.Header().Set("Content-Type", "application/x-tar")
		if _, err := io.WriteString(w, "stream payload"); err != nil {
			panic(err)
		}
	})

	rc, err := open(apiCtx)
	Expect(err).NotTo(HaveOccurred())
	Expect(collector.Summary()).To(BeEmpty(), "the operation must stay in flight until the stream is consumed")

	data, err := io.ReadAll(rc)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(data)).To(Equal("stream payload"))
	Expect(rc.Close()).To(Succeed())

	Expect(collector.Summary()).To(HaveLen(1))
	Expect(operationCount(collector, label)).To(Equal(1), "reading to EOF and closing must record the operation once")
},
	Entry("image save", opstats.Operation("docker: image save"), func(ctx context.Context) (io.ReadCloser, error) {
		return CliImageSaveToStream(ctx, "img")
	}),
	Entry("container copy", opstats.Operation("docker: container copy"), func(ctx context.Context) (io.ReadCloser, error) {
		return ContainerCopyFrom(ctx, "c", "/src")
	}),
)

var _ = DescribeTable("docker stream operations failing before the stream", func(ctx SpecContext, label opstats.Operation, open func(ctx context.Context) (io.ReadCloser, error)) {
	apiCtx, collector := observedDaemonContext(http.HandlerFunc(respondError))

	_, err := open(apiCtx)
	Expect(err).To(HaveOccurred())

	Expect(operationCount(collector, label)).To(Equal(1), "a failure before the stream must still record the operation")
},
	Entry("image save", opstats.Operation("docker: image save"), func(ctx context.Context) (io.ReadCloser, error) {
		return CliImageSaveToStream(ctx, "img")
	}),
	Entry("container copy", opstats.Operation("docker: container copy"), func(ctx context.Context) (io.ReadCloser, error) {
		return ContainerCopyFrom(ctx, "c", "/src")
	}),
)

var _ = Describe("docker cli run", func() {
	const createDelay = 300 * time.Millisecond

	It("measures the whole cli run, not just the container start request", func(ctx SpecContext) {
		for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION", "WERF_DEBUG_DOCKER"} {
			GinkgoT().Setenv(key, "")
		}

		server := newDelayedCreateServer(createDelay)
		GinkgoT().Setenv("DOCKER_HOST", "tcp://"+server)
		Expect(InitDockerConfig(InitOptions{DockerConfigDir: GinkgoT().TempDir()})).To(Succeed())

		cliCtx, err := NewContextWithStreams(context.Background(), io.Discard, io.Discard)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(apiCli(cliCtx).Close)

		collector := opstats.NewCollector()
		Expect(CliRun(opstats.NewContext(cliCtx, collector), "img")).NotTo(Succeed())

		summary := collector.Summary()
		Expect(summary).To(HaveLen(1))
		Expect(summary[0].Operation).To(Equal(opstats.Operation("docker: container run")))
		Expect(summary[0].Count).To(Equal(1))
		Expect(summary[0].TotalTime).To(BeNumerically(">=", createDelay), "the timer must cover the container create request too")
	})
})
