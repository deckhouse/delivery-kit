package build

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
)

var _ = ginkgo.Describe("native service file builder selection", func() {
	ginkgo.DescribeTable("uses only the active builder", func(ctx ginkgo.SpecContext, dockerfile, staged bool) {
		img := container_backend.NewLegacyStageImage(nil, "stage", nil, "linux/amd64")
		builder := stage_builder.NewStageBuilder(nil, "", img)
		builder.StapelStageBuilder().AddCommands("true")
		if dockerfile {
			if staged {
				builder.DockerfileStageBuilder()
			} else {
				builder.DockerfileBuilder()
			}
		}
		stg := newJSObserverStage(stage.Install)
		stg.SetStageImage(&stage.StageImage{Image: img, Builder: builder})
		files := nativeStageServiceFiles(ctx, stg)
		if dockerfile {
			gomega.Expect(files).To(gomega.BeEmpty())
		} else {
			gomega.Expect(files).To(gomega.Equal([]string{container_backend.ServiceScriptPath}))
		}
	}, ginkgo.Entry("native", false, false), ginkgo.Entry("Dockerfile", true, false), ginkgo.Entry("staged Dockerfile", true, true))
	ginkgo.It("does not trust mounts from the inactive legacy builder", func(ctx ginkgo.SpecContext) {
		img := container_backend.NewLegacyStageImage(nil, "stage", nil, "linux/amd64")
		builder := stage_builder.NewStageBuilder(nil, "", img)
		builder.LegacyStapelStageBuilder().BuilderContainer().MountSSHAgentSocket("/host/agent.sock")
		builder.StapelStageBuilder().AddCommands("true")
		stg := newJSObserverStage(stage.Install)
		stg.SetStageImage(&stage.StageImage{Image: img, Builder: builder})
		gomega.Expect(nativeStageServiceFiles(ctx, stg)).To(gomega.Equal([]string{container_backend.ServiceScriptPath}))
	})
})
