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

var _ = Describe("artifact stages", func() {
	It("stores artifact identity and lifecycle flags", func() {
		base := NewBaseStage(Sbom, &BaseStageOptions{})
		metadata := &ArtifactStageMetadata{
			Kind:           ArtifactKindSbom,
			ParentDigest:   "sha256:parent",
			TargetPlatform: "linux/amd64",
			Mutable:        true,
			Buildable:      false,
		}

		base.SetArtifactMetadata(metadata)

		Expect(base.GetArtifactMetadata()).To(BeIdenticalTo(metadata))
		Expect(base.GetArtifactMetadata().Kind).To(Equal(ArtifactKindSbom))
		Expect(base.GetArtifactMetadata().ParentDigest).To(Equal("sha256:parent"))
		Expect(base.GetArtifactMetadata().TargetPlatform).To(Equal("linux/amd64"))
		Expect(base.GetArtifactMetadata().Mutable).To(BeTrue())
		Expect(base.GetArtifactMetadata().Buildable).To(BeFalse())
	})

	DescribeTable("is mutable and non-buildable",
		func(artifactStage Interface) {
			Expect(artifactStage.IsMutable()).To(BeTrue())
			Expect(artifactStage.IsBuildable()).To(BeFalse())
		},
		Entry("SBOM", GenerateSbomStage(&BaseStageOptions{TargetPlatform: "linux/amd64"}, signing.SbomSigningOptions{}, "dependency", func(context.Context, *image.StageDesc, string, string) error {
			return nil
		})),
		Entry("VEX", GenerateVexStage([]byte(`{"statements":[]}`), &BaseStageOptions{TargetPlatform: "linux/amd64"}, signing.VexSigningOptions{})),
	)

	It("includes the parent descriptor in artifact stage dependencies", func(ctx SpecContext) {
		sbom := GenerateSbomStage(&BaseStageOptions{TargetPlatform: "linux/amd64"}, signing.SbomSigningOptions{}, "dependency", func(context.Context, *image.StageDesc, string, string) error {
			return nil
		})
		withoutParent, err := sbom.GetDependencies(ctx, nil, nil, nil, nil, nil)
		Expect(err).To(Succeed())

		ctrl := gomock.NewController(GinkgoT())
		parentImage := mock.NewMockLegacyImageInterface(ctrl)
		parentImage.EXPECT().GetStageDesc().Return(&image.StageDesc{Info: &image.Info{RepoDigest: "repo@sha256:parent"}})
		parent := NewStageImage(NewContainerBackendStub(), "", parentImage)
		withParent, err := sbom.GetDependencies(ctx, nil, nil, nil, parent, nil)
		Expect(err).To(Succeed())
		Expect(withParent).NotTo(Equal(withoutParent))
	})
})
