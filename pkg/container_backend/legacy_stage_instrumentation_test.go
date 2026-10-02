package container_backend

import (
	"context"
	"errors"
	"net/http"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/opstats"
)

var _ = ginkgo.Describe("Legacy stage container instrumentation", func() {
	ginkgo.It("measures the inspect of the base image without measuring werf-level preparation", func() {
		ctx, collector := dockerDaemonContext(daemonHandler(http.StatusInternalServerError, `{"message":"daemon failure"}`))

		backend := &DockerServerBackend{}
		image := &LegacyStageImage{
			legacyBaseImage: newLegacyBaseImage("stage", backend),
			targetPlatform:  "linux/amd64",
			fromImage: &LegacyStageImage{
				legacyBaseImage: newLegacyBaseImage("base", backend),
			},
		}
		container := newLegacyStageImageContainer(image)

		gomega.Expect(container.run(ctx)).NotTo(gomega.Succeed())

		gomega.Expect(operationCount(collector, "docker: image inspect")).To(gomega.Equal(1))
		gomega.Expect(collector.Summary()).To(gomega.HaveLen(1), "the stage preparation must not be measured")
		gomega.Expect(operationCount(collector, "docker: container run")).To(gomega.Equal(0), "the run must not be measured when the preparation fails")
	})
})

var _ = ginkgo.Describe("DockerServerBackend Dockerfile build instrumentation", func() {
	ginkgo.It("measures the build as a single docker image build operation", func() {
		collector := opstats.NewCollector()
		ctx := opstats.NewContext(context.Background(), collector)

		_, err := (&DockerServerBackend{}).BuildDockerfile(ctx, []byte("FROM scratch\n"), BuildDockerfileOpts{
			DockerfileCtxRelPath: "../Dockerfile",
			BuildContextArchive:  &stubBuildContextArchive{err: errors.New("extraction failed")},
		})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("extraction failed")))

		summary := collector.Summary()
		gomega.Expect(summary).To(gomega.HaveLen(1))
		gomega.Expect(summary[0].Operation).To(gomega.Equal(opstats.Operation("docker: image build")))
		gomega.Expect(summary[0].Count).To(gomega.Equal(1))
	})
})

var _ = ginkgo.Describe("DockerServerBackend image inspection instrumentation", func() {
	ginkgo.It("reports the daemon request without wrapping it into a second operation", func() {
		ctx, collector := dockerDaemonContext(daemonHandler(http.StatusOK, `{"Id":"sha256:abc","Os":"linux","Architecture":"amd64","Created":"2020-01-01T00:00:00Z","Config":{}}`))

		info, err := (&DockerServerBackend{}).GetImageInfo(ctx, "img", GetImageInfoOpts{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(info).NotTo(gomega.BeNil())

		summary := collector.Summary()
		gomega.Expect(summary).To(gomega.HaveLen(1), "the backend must not add an operation of its own around the daemon request")
		gomega.Expect(summary[0].Operation).To(gomega.Equal(opstats.Operation("docker: image inspect")))
		gomega.Expect(summary[0].Count).To(gomega.Equal(1))
	})
})
