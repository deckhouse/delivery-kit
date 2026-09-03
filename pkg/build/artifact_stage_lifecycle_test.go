package build

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	build_image "github.com/werf/werf/v2/pkg/build/image"
	"github.com/werf/werf/v2/pkg/build/signing"
	"github.com/werf/werf/v2/pkg/build/stage"
	imagePkg "github.com/werf/werf/v2/pkg/image"
)

type restoredArtifactPhase struct {
	Phase
	called []stage.StageName
}

func (p *restoredArtifactPhase) OnImageStage(_ context.Context, _ *build_image.Image, stg stage.Interface) error {
	p.called = append(p.called, stg.Name())
	return nil
}

var _ = Describe("restored artifact stages", func() {
	It("runs artifact stages without replaying ordinary image stages", func(ctx SpecContext) {
		sbom := stage.GenerateSbomStage(
			&stage.BaseStageOptions{TargetPlatform: "linux/amd64"},
			signing.SbomSigningOptions{},
			"scanner-input",
			func(context.Context, *imagePkg.StageDesc, string, string) error { return nil },
		)
		regular := stage.GenerateImageSpecStage(nil, &stage.BaseStageOptions{})
		img := &build_image.Image{}
		img.SetStages([]stage.Interface{regular, sbom})
		phase := &restoredArtifactPhase{}

		Expect(runRestoredArtifactStages(ctx, img, phase)).To(Succeed())
		Expect(phase.called).To(Equal([]stage.StageName{stage.Sbom}))
	})
})
