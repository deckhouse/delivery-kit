package shippedscope

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Produced stage overlay boundaries", func() {
	ginkgo.DescribeTable("recognizes a file restored after an excluded stage removed its original entry", func(ctx ginkgo.SpecContext, excluded tarEntry) {
		binary := string(goBinary())
		img, err := imageOf([]tarEntry{regularFile("bin/app", binary)}, []tarEntry{excluded}, []tarEntry{regularFile("bin/app", binary)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 2, End: 3}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
	},
		ginkgo.Entry("symlink replacement", symlink("bin/app", "elsewhere")),
		ginkgo.Entry("directory whiteout", whiteout(".wh.bin")),
		ginkgo.Entry("root opaque whiteout", whiteout(".wh..wh..opq")),
		ginkgo.Entry("directory replacement", directory("bin/app")),
	)

	ginkgo.It("keeps cross-layer hardlink uncertainty even when its current target appears intact", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("z", string(goBinary()))}, []tarEntry{hardlink("a", "z")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 0, End: 1}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeTrue())
		gomega.Expect(produced.Known).To(gomega.BeFalse())
	})

	ginkgo.DescribeTable("does not lose surviving bytes when a cross-layer hardlink target changes", func(ctx ginkgo.SpecContext, removed bool) {
		last := regularFile("z", "replacement")
		if removed {
			last = whiteout(".wh.z")
		}
		img, err := imageOf([]tarEntry{regularFile("z", string(goBinary()))}, []tarEntry{hardlink("a", "z")}, []tarEntry{last})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeTrue())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 1, End: 2}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeFalse())
	}, ginkgo.Entry("replaced target", false), ginkgo.Entry("deleted target", true))

	ginkgo.It("ignores identical bytes rewritten at the same path", func(ctx ginkgo.SpecContext) {
		body := string(goBinary())
		img, err := imageOf([]tarEntry{regularFile("app", body)}, []tarEntry{regularFile("app", body)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 1, End: 2}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("does not infer complete production from an incomplete intermediate snapshot", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{hardlink("dangling", "absent")}, []tarEntry{whiteout(".wh.dangling"), regularFile("app", string(goBinary()))})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 1, End: 2}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeFalse())
	})

	ginkgo.It("accepts an eligible stage with no appended layers", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("app", string(goBinary()))})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 0, End: 1}, {Start: 1, End: 1}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
	})
})
