package stage

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("SBOM build context declaration labels", func() {
	// The producer intent is build-time input of this image only: it never travels to
	// the image config, however the build spelled it or asked for it to be kept.
	ginkgo.DescribeTable("never reach the image config", func(ctx ginkgo.SpecContext, labels, addLabels map[string]string, removeLabels []string, keepEssentialWerfLabels bool, kept gomega.OmegaMatcher) {
		stg := ImageSpecStage{BaseStage: &BaseStage{stageImage: &StageImage{Image: NewLegacyImageStub()}}}

		modified, err := stg.modifyLabels(ctx, labels, addLabels, removeLabels, keepEssentialWerfLabels)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(modified).NotTo(gomega.HaveKey(SBOMBuildContextLabel))
		gomega.Expect(modified).To(kept)
	},
		ginkgo.Entry("declared by the image spec of this build",
			map[string]string{"keep": "me"},
			map[string]string{SBOMBuildContextLabel: `{"version":1}`}, nil, false,
			gomega.HaveKeyWithValue("keep", "me")),
		ginkgo.Entry("inherited from a base image that carried one",
			map[string]string{"keep": "me", SBOMBuildContextLabel: `{"version":1}`},
			map[string]string{}, nil, false,
			gomega.HaveKeyWithValue("keep", "me")),
		ginkgo.Entry("declared while every label is removed and the werf ones are kept",
			map[string]string{"keep": "me"},
			map[string]string{SBOMBuildContextLabel: `{"version":1}`}, []string{"/.*/"}, true,
			gomega.Not(gomega.HaveKey("keep"))),
	)

	ginkgo.It("leaves the declaration of the image configuration where the build reads it", func(ctx ginkgo.SpecContext) {
		stg := ImageSpecStage{BaseStage: &BaseStage{stageImage: &StageImage{Image: NewLegacyImageStub()}}}
		declared := map[string]string{SBOMBuildContextLabel: `{"version":1}`}

		_, err := stg.modifyLabels(ctx, map[string]string{SBOMBuildContextLabel: `{"version":1}`}, declared, nil, false)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declared).To(gomega.HaveKey(SBOMBuildContextLabel), "stripping the published label does not rewrite the producer intent")
	})
})
