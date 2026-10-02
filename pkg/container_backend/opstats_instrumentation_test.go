package container_backend

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/opstats"
	"github.com/werf/werf/v2/pkg/werf"
	"github.com/werf/werf/v2/test/pkg/buildahstub"
)

// removedOperations are the aggregate and werf-level operations the backends used to report.
// They are now covered by the docker and buildah leaf operations and must not be emitted.
var removedOperations = []opstats.Operation{
	opstats.OperationStageBuild,
	opstats.OperationImageInspect,
	opstats.OperationImagePull,
	opstats.OperationImagePush,
	opstats.OperationImageSaveLoad,
	opstats.OperationImportChecksum,
}

func expectNoRemovedOperations(collector *opstats.Collector) {
	ginkgo.GinkgoHelper()
	for _, op := range removedOperations {
		gomega.Expect(operationCount(collector, op)).To(gomega.Equal(0), "%s must no longer be collected", op)
	}
}

var _ = ginkgo.Describe("Legacy stage container instrumentation", func() {
	ginkgo.It("measures the inspect of the base image without measuring werf-level preparation", func() {
		ctx, collector := dockerDaemonContext(daemonHandler(http.StatusInternalServerError, `{"message":"daemon failure"}`))

		backend := &DockerServerBackend{}
		img := &LegacyStageImage{
			legacyBaseImage: newLegacyBaseImage("stage", backend),
			targetPlatform:  "linux/amd64",
			fromImage: &LegacyStageImage{
				legacyBaseImage: newLegacyBaseImage("base", backend),
			},
		}
		container := newLegacyStageImageContainer(img)

		gomega.Expect(container.run(ctx)).NotTo(gomega.Succeed())

		gomega.Expect(operationCount(collector, "docker: image inspect")).To(gomega.Equal(1))
		gomega.Expect(collector.Summary()).To(gomega.HaveLen(1), "the stage preparation must not be measured")
		gomega.Expect(operationCount(collector, "docker: container run")).To(gomega.Equal(0), "the run must not be measured when the preparation fails")
		expectNoRemovedOperations(collector)
	})
})

var _ = ginkgo.Describe("DockerServerBackend instrumentation", func() {
	ginkgo.It("does not measure the build context preparation that precedes the build", func() {
		gomega.Expect(werf.Init(ginkgo.GinkgoT().TempDir(), "")).To(gomega.Succeed())

		collector := opstats.NewCollector()
		ctx := opstats.NewContext(context.Background(), collector)

		_, err := (&DockerServerBackend{}).BuildDockerfile(ctx, []byte("FROM scratch\n"), BuildDockerfileOpts{
			DockerfileCtxRelPath: "Dockerfile",
			BuildContextArchive:  &stubBuildContextArchive{path: filepath.Join(ginkgo.GinkgoT().TempDir(), "missing.tar")},
		})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unable to open context archive")))

		gomega.Expect(collector.Summary()).To(gomega.BeEmpty(), "the build is measured by the docker CLI build handler, not by the backend preparation")
	})

	ginkgo.It("reports the daemon request without wrapping it into a second operation", func() {
		ctx, collector := dockerDaemonContext(daemonHandler(http.StatusOK, `{"Id":"sha256:abc","Os":"linux","Architecture":"amd64","Created":"2020-01-01T00:00:00Z","Config":{}}`))

		info, err := (&DockerServerBackend{}).GetImageInfo(ctx, "img", GetImageInfoOpts{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(info).NotTo(gomega.BeNil())

		summary := collector.Summary()
		gomega.Expect(summary).To(gomega.HaveLen(1), "the backend must not add an operation of its own around the daemon request")
		gomega.Expect(summary[0].Operation).To(gomega.Equal(opstats.Operation("docker: image inspect")))
		gomega.Expect(summary[0].Count).To(gomega.Equal(1))
		expectNoRemovedOperations(collector)
	})
})

var _ = ginkgo.Describe("BuildahBackend operation stats", func() {
	var (
		collector *opstats.Collector
		ctx       context.Context
	)

	ginkgo.BeforeEach(func() {
		gomega.Expect(werf.Init(ginkgo.GinkgoT().TempDir(), "")).To(gomega.Succeed())

		collector = opstats.NewCollector()
		ctx = opstats.NewContext(context.Background(), collector)
	})

	ginkgo.It("does not measure the Dockerfile build preparation", func() {
		var atBuild []opstats.OperationSummary
		stub := &dockerfileBuildStub{onBuild: func(_ context.Context) {
			atBuild = collector.Summary()
		}}

		imageID, err := NewBuildahBackend(stub, BuildahBackendOptions{}).BuildDockerfile(ctx, []byte("FROM scratch\n"), BuildDockerfileOpts{
			BuildContextArchive: &stubBuildContextArchive{dir: ginkgo.GinkgoT().TempDir()},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(imageID).To(gomega.Equal("sha256:built"))

		gomega.Expect(atBuild).To(gomega.BeEmpty(), "the preparation of the build context is a werf-level step and must not be measured")
		gomega.Expect(collector.Summary()).To(gomega.BeEmpty())
	})

	ginkgo.It("does not measure a failed build context extraction as a build", func() {
		_, err := NewBuildahBackend(&dockerfileBuildStub{}, BuildahBackendOptions{}).BuildDockerfile(ctx, []byte("FROM scratch\n"), BuildDockerfileOpts{
			BuildContextArchive: &stubBuildContextArchive{err: errors.New("extraction failed")},
		})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("extraction failed")))

		gomega.Expect(collector.Summary()).To(gomega.BeEmpty())
	})

	ginkgo.It("does not aggregate the whole Stapel stage build", func() {
		_, err := NewBuildahBackend(&buildahstub.BuildahStub{}, BuildahBackendOptions{}).BuildStapelStage(ctx, "base-image", BuildStapelStageOptions{})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		gomega.Expect(collector.Summary()).To(gomega.BeEmpty())
		expectNoRemovedOperations(collector)
	})
})
