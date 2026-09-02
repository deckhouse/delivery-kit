package stage

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/build/signing"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("SbomStage dependencies", func() {
	It("changes when the target platform changes", func(ctx SpecContext) {
		newStage := func(platform string) *SbomStage {
			return GenerateSbomStage(&BaseStageOptions{TargetPlatform: platform}, signing.SbomSigningOptions{}, "scanner-input", func(context.Context, *image.StageDesc, string, string) error {
				return nil
			})
		}

		amd, err := newStage("linux/amd64").GetDependencies(ctx, nil, nil, nil, nil, nil)
		Expect(err).To(Succeed())
		arm, err := newStage("linux/arm64").GetDependencies(ctx, nil, nil, nil, nil, nil)
		Expect(err).To(Succeed())

		Expect(amd).NotTo(Equal(arm))
		content, err := newStage("linux/amd64").GetContentDependencies(ctx, nil, nil)
		Expect(err).To(Succeed())
		Expect(content).To(Equal(amd))
	})

	It("changes when the effective SBOM inputs change", func(ctx SpecContext) {
		newDependencies := func(inputs string) string {
			stage := GenerateSbomStage(&BaseStageOptions{TargetPlatform: "linux/amd64"}, signing.SbomSigningOptions{}, inputs, func(context.Context, *image.StageDesc, string, string) error {
				return nil
			})
			dependencies, err := stage.GetDependencies(ctx, nil, nil, nil, nil, nil)
			Expect(err).To(Succeed())
			return dependencies
		}

		Expect(newDependencies("scanner=v1;merge=v1;gost=yes")).NotTo(Equal(newDependencies("scanner=v2;merge=v1;gost=yes")))
		Expect(newDependencies("scanner=v1;merge=v1;gost=yes")).NotTo(Equal(newDependencies("scanner=v1;merge=v2;gost=yes")))
	})

	It("changes when the parent manifest digest changes", func(ctx SpecContext) {
		newDependencies := func(digest string) string {
			ctrl := gomock.NewController(GinkgoT())
			parentImage := mock.NewMockLegacyImageInterface(ctrl)
			parentImage.EXPECT().GetStageDesc().Return(&image.StageDesc{Info: &image.Info{RepoDigest: "repo@" + digest}})
			parent := NewStageImage(NewContainerBackendStub(), "", parentImage)
			stage := GenerateSbomStage(&BaseStageOptions{TargetPlatform: "linux/amd64"}, signing.SbomSigningOptions{}, "scanner-input", func(context.Context, *image.StageDesc, string, string) error {
				return nil
			})
			dependencies, err := stage.GetDependencies(ctx, nil, nil, nil, parent, nil)
			Expect(err).To(Succeed())
			return dependencies
		}

		Expect(newDependencies("sha256:one")).NotTo(Equal(newDependencies("sha256:two")))
	})
})
