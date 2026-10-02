package docker

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"golang.org/x/net/context"

	"github.com/werf/werf/v2/pkg/opstats"
)

const loadResponseBody = `{"stream":"Loaded image ID: sha256:26b2eb03618e749084668eaff68cff8f81dda12d06ac641be7a6398b82a6f25b\n"}`

var _ = ginkgo.DescribeTable("docker api operations", func(label opstats.Operation, handler http.Handler, call func(ctx context.Context) error, expectError bool) {
	apiCtx, collector := observedDaemonContext(handler)

	err := call(apiCtx)
	if expectError {
		gomega.Expect(err).To(gomega.HaveOccurred())
	} else {
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}

	gomega.Expect(collector.Summary()).To(gomega.HaveLen(1), "exactly one operation must be recorded")
	gomega.Expect(operationCount(collector, label)).To(gomega.Equal(1))
},
	ginkgo.Entry("image list", opstats.Operation("docker: image list"), respondJSON(`[]`), func(ctx context.Context) error {
		_, err := Images(ctx, types.ImageListOptions{})
		return err
	}, false),
	ginkgo.Entry("image list failure", opstats.Operation("docker: image list"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := Images(ctx, types.ImageListOptions{})
		return err
	}, true),
	ginkgo.Entry("image inspect", opstats.Operation("docker: image inspect"), respondJSON(`{"Id":"sha256:abc"}`), func(ctx context.Context) error {
		_, err := ImageInspect(ctx, "img")
		return err
	}, false),
	ginkgo.Entry("image inspect failure", opstats.Operation("docker: image inspect"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := ImageInspect(ctx, "img")
		return err
	}, true),
	ginkgo.Entry("image prune", opstats.Operation("docker: image prune"), respondJSON(`{"ImagesDeleted":[],"SpaceReclaimed":0}`), func(ctx context.Context) error {
		_, err := ImagesPrune(ctx, ImagesPruneOptions{})
		return err
	}, false),
	ginkgo.Entry("image load", opstats.Operation("docker: image load"), respondJSON(loadResponseBody), func(ctx context.Context) error {
		_, err := CliLoadFromStream(ctx, strings.NewReader(""))
		return err
	}, false),
	ginkgo.Entry("image load failure", opstats.Operation("docker: image load"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := CliLoadFromStream(ctx, strings.NewReader(""))
		return err
	}, true),
	ginkgo.Entry("container list", opstats.Operation("docker: container list"), respondJSON(`[]`), func(ctx context.Context) error {
		_, err := Containers(ctx, types.ContainerListOptions{})
		return err
	}, false),
	ginkgo.Entry("container inspect", opstats.Operation("docker: container inspect"), respondJSON(`{"Id":"c"}`), func(ctx context.Context) error {
		_, err := ContainerInspect(ctx, "c")
		return err
	}, false),
	ginkgo.Entry("container commit", opstats.Operation("docker: container commit"), respondJSON(`{"Id":"sha256:abc"}`), func(ctx context.Context) error {
		_, err := ContainerCommit(ctx, "c", types.ContainerCommitOptions{})
		return err
	}, false),
	ginkgo.Entry("container commit failure", opstats.Operation("docker: container commit"), http.HandlerFunc(respondError), func(ctx context.Context) error {
		_, err := ContainerCommit(ctx, "c", types.ContainerCommitOptions{})
		return err
	}, true),
	ginkgo.Entry("container remove", opstats.Operation("docker: container remove"), respondJSON(``), func(ctx context.Context) error {
		return ContainerRemove(ctx, "c", types.ContainerRemoveOptions{})
	}, false),
)

var _ = ginkgo.DescribeTable("docker stream operations", func(label opstats.Operation, open func(ctx context.Context) (io.ReadCloser, error)) {
	apiCtx, collector := observedDaemonContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			writePing(w)
			return
		}
		w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString([]byte(`{"name":"src","size":14,"mode":420,"mtime":"2020-01-01T00:00:00Z"}`)))
		w.Header().Set("Content-Type", "application/x-tar")
		if _, err := io.WriteString(w, "stream payload"); err != nil {
			panic(err)
		}
	}))

	rc, err := open(apiCtx)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(collector.Summary()).To(gomega.BeEmpty(), "the operation must stay in flight until the stream is consumed")

	data, err := io.ReadAll(rc)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(string(data)).To(gomega.Equal("stream payload"))
	gomega.Expect(rc.Close()).To(gomega.Succeed())

	gomega.Expect(collector.Summary()).To(gomega.HaveLen(1))
	gomega.Expect(operationCount(collector, label)).To(gomega.Equal(1), "reading to EOF and closing must record the operation once")
},
	ginkgo.Entry("image save", opstats.Operation("docker: image save"), func(ctx context.Context) (io.ReadCloser, error) {
		return CliImageSaveToStream(ctx, "img")
	}),
	ginkgo.Entry("container copy", opstats.Operation("docker: container copy"), func(ctx context.Context) (io.ReadCloser, error) {
		return ContainerCopyFrom(ctx, "c", "/src")
	}),
)

var _ = ginkgo.DescribeTable("docker stream operations failing before the stream", func(label opstats.Operation, open func(ctx context.Context) (io.ReadCloser, error)) {
	apiCtx, collector := observedDaemonContext(http.HandlerFunc(respondError))

	_, err := open(apiCtx)
	gomega.Expect(err).To(gomega.HaveOccurred())

	gomega.Expect(collector.Summary()).To(gomega.HaveLen(1))
	gomega.Expect(operationCount(collector, label)).To(gomega.Equal(1), "a failure before the stream must still record the operation")
},
	ginkgo.Entry("image save", opstats.Operation("docker: image save"), func(ctx context.Context) (io.ReadCloser, error) {
		return CliImageSaveToStream(ctx, "img")
	}),
	ginkgo.Entry("container copy", opstats.Operation("docker: container copy"), func(ctx context.Context) (io.ReadCloser, error) {
		return ContainerCopyFrom(ctx, "c", "/src")
	}),
)

var _ = ginkgo.DescribeTable("docker cli operations", func(label opstats.Operation, call func(ctx context.Context) error) {
	cliCtx := cliDaemonContext(newMissingImageDaemonServer())

	collector := opstats.NewCollector()
	gomega.Expect(call(opstats.NewContext(cliCtx, collector))).NotTo(gomega.Succeed())

	summary := collector.Summary()
	gomega.Expect(summary).To(gomega.HaveLen(1), "exactly one operation must be recorded")
	gomega.Expect(summary[0].Operation).To(gomega.Equal(label))
	gomega.Expect(summary[0].Count).To(gomega.Equal(1))
},
	ginkgo.Entry("pull", opstats.Operation("docker: image pull"), func(ctx context.Context) error {
		return CliPull(ctx, "img")
	}),
	ginkgo.Entry("push", opstats.Operation("docker: image push"), func(ctx context.Context) error {
		return CliPushWithRetries(ctx, "img")
	}),
	ginkgo.Entry("tag", opstats.Operation("docker: image tag"), func(ctx context.Context) error {
		return CliTag(ctx, "img", "img2")
	}),
	ginkgo.Entry("rmi", opstats.Operation("docker: image remove"), func(ctx context.Context) error {
		return CliRmi(ctx, "img")
	}),
	ginkgo.Entry("create", opstats.Operation("docker: container create"), func(ctx context.Context) error {
		return CliCreate(ctx, "img")
	}),
	ginkgo.Entry("rm", opstats.Operation("docker: container remove"), func(ctx context.Context) error {
		return CliRm(ctx, "c")
	}),
)

var _ = ginkgo.Describe("docker cli build", func() {
	ginkgo.DescribeTable("measures the cli build itself once, whichever builder handles it", func(buildx bool) {
		previousUseBuildx := useBuildx
		useBuildx = buildx
		ginkgo.DeferCleanup(func() { useBuildx = previousUseBuildx })

		cliCtx := cliDaemonContext(newMissingImageDaemonServer())

		collector := opstats.NewCollector()
		err := CliBuild_LiveOutputWithCustomIn(opstats.NewContext(cliCtx, collector), io.NopCloser(strings.NewReader("")), "-")
		gomega.Expect(err).To(gomega.HaveOccurred())

		summary := collector.Summary()
		gomega.Expect(summary).To(gomega.HaveLen(1), "exactly one operation must be recorded")
		gomega.Expect(summary[0].Operation).To(gomega.Equal(opstats.Operation("docker: image build")))
		gomega.Expect(summary[0].Count).To(gomega.Equal(1), "the legacy and buildx handlers must not double count")
	},
		ginkgo.Entry("legacy builder", false),
		ginkgo.Entry("buildx builder", true),
	)
})

var _ = ginkgo.Describe("docker cli run", func() {
	const createDelay = 300 * time.Millisecond

	ginkgo.It("measures the whole cli run, not just the container start request", func() {
		cliCtx := cliDaemonContext(newDelayedCreateServer(createDelay))

		collector := opstats.NewCollector()
		gomega.Expect(CliRun(opstats.NewContext(cliCtx, collector), "img")).NotTo(gomega.Succeed())

		summary := collector.Summary()
		gomega.Expect(summary).To(gomega.HaveLen(1))
		gomega.Expect(summary[0].Operation).To(gomega.Equal(opstats.Operation("docker: container run")))
		gomega.Expect(summary[0].Count).To(gomega.Equal(1))
		gomega.Expect(summary[0].TotalTime).To(gomega.BeNumerically(">=", createDelay), "the timer must cover the container create request too")
	})
})
