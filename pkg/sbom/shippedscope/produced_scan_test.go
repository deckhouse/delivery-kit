package shippedscope

import (
	"bytes"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/logboek"
)

var _ = ginkgo.Describe("Produced binary scan cost", func() {
	ginkgo.It("classifies only eligible layers and reports the boundary reconstruction cost", func(ctx ginkgo.SpecContext) {
		binary := string(goBinary())
		base, err := layerOf(regularFile("base", binary))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		eligible, err := layerOf(regularFile("app", binary))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		excluded, err := layerOf(regularFile("other", binary))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		baseCounted := &countedLayer{Layer: base}
		eligibleCounted := &countedLayer{Layer: eligible}
		excludedCounted := &countedLayer{Layer: excluded}
		img, err := mutate.AppendLayers(empty.Image, baseCounted, eligibleCounted, excludedCounted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		baseCounted.opens, eligibleCounted.opens, excludedCounted.opens = 0, 0, 0
		var output bytes.Buffer
		logCtx := logboek.NewContext(ctx, logboek.NewLogger(&output, &output))
		produced, err := CollectProducedFiles(logCtx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 1, End: 2}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Classification.Go).To(gomega.Equal(VerdictNames))
		gomega.Expect(baseCounted.opens).To(gomega.Equal(2), "the base is read only for the two filesystem boundaries")
		gomega.Expect(eligibleCounted.opens).To(gomega.Equal(2), "one boundary pass and one classification pass")
		gomega.Expect(excludedCounted.opens).To(gomega.BeZero(), "the final filesystem was already indexed")
		gomega.Expect(output.String()).To(gomega.ContainSubstring("2 filesystem boundary passes, 1 scanned layers"))
		gomega.Expect(output.String()).To(gomega.MatchRegexp(`Produced binaries:.*\([0-9].*\)`))
	})
})
