package stage

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image"
)

var _ = ginkgo.Describe("SBOM provenance labels", func() {
	ginkgo.DescribeTable("survive imageSpec label removal", func(ctx ginkgo.SpecContext, pattern string) {
		stg := ImageSpecStage{BaseStage: &BaseStage{stageImage: &StageImage{Image: NewLegacyImageStub()}}}
		labels := map[string]string{image.WerfSBOMStageLabel: "bound-stage-record", "unrelated": "remove"}

		modified, err := stg.modifyLabels(ctx, labels, map[string]string{}, []string{pattern}, false)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(modified).To(gomega.HaveKeyWithValue(image.WerfSBOMStageLabel, "bound-stage-record"))
		gomega.Expect(labels).To(gomega.HaveKeyWithValue(image.WerfSBOMStageLabel, "bound-stage-record"))
	},
		ginkgo.Entry("exact reserved key", image.WerfSBOMStageLabel),
		ginkgo.Entry("remove all labels", "/.*/"),
	)
})
