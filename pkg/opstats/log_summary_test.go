package opstats

import (
	"bytes"
	"context"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/logboek"
	"github.com/werf/logboek/pkg/level"
)

var _ = ginkgo.Describe("LogSummary", func() {
	ginkgo.It("prints the backend leaf operations under their collected names", func() {
		collector := NewCollector()
		for _, op := range []Operation{"docker: image build", "docker: container run", "registry: image get", OperationGitFetch, OperationStageLockWait} {
			collector.add(op, time.Now(), time.Now().Add(time.Second))
		}
		CountEvent(NewContext(context.Background(), collector), EventStageBuilt)

		var out bytes.Buffer
		logger := logboek.NewLogger(&out, &out)
		logger.SetAcceptedLevel(level.Debug)
		LogSummary(logboek.NewContext(context.Background(), logger), collector, "command time", 5*time.Second)

		rendered := out.String()
		gomega.Expect(rendered).NotTo(gomega.ContainSubstring("command time:"))
		gomega.Expect(rendered).NotTo(gomega.ContainSubstring("wall must not exceed"))
		for _, expected := range []string{"docker: image build", "docker: container run", "registry: image get", "git: fetch", "sync: lock acquire", "built"} {
			gomega.Expect(rendered).To(gomega.ContainSubstring(expected))
		}
		for _, removed := range []Operation{OperationStageBuild, OperationImageInspect, OperationImagePull, OperationImageSaveLoad, OperationDockerDaemon, OperationConfigRender, OperationGiterminismInit, OperationStapelContainer} {
			gomega.Expect(rendered).NotTo(gomega.ContainSubstring(string(removed)))
		}
	})
})
