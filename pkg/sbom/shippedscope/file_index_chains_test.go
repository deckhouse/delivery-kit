package shippedscope

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Same-layer hardlink chains", func() {
	ginkgo.It("keeps captured historical bytes after the terminal target is replaced", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{hardlink("a", "b"), hardlink("b", "origin"), regularFile("origin", "old")}, []tarEntry{regularFile("origin", "new")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, captured, err := indexImageFiles(ctx, img, func(name string) bool { return name == "/a" })
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(index.Files["/a"].Digest).To(gomega.Equal(digestOf("old")))
		gomega.Expect(index.Files["/b"].Digest).To(gomega.Equal(digestOf("old")))
		gomega.Expect(index.Files["/origin"].Digest).To(gomega.Equal(digestOf("new")))
		gomega.Expect(captured).To(gomega.HaveKeyWithValue("/a", []byte("old")))
	})

	ginkgo.It("keeps chained symlinks bound to their owning layer", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{hardlink("a", "b"), hardlink("b", "origin"), symlink("origin", "old")}, []tarEntry{symlink("origin", "new")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(index.Symlinks).To(gomega.HaveKeyWithValue("/a", "old"))
		gomega.Expect(index.Files).NotTo(gomega.HaveKey("/a"))
	})

	ginkgo.It("does not claim completeness when an intermediate target only resolves in the flattened view", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{hardlink("a", "b"), hardlink("b", "origin"), regularFile("origin", "old")}, []tarEntry{regularFile("b", "new")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeTrue())
	})

	ginkgo.It("classifies produced content that survives only through same-layer chains", func(ctx ginkgo.SpecContext) {
		binary := string(goBinary())
		img, err := imageOf([]tarEntry{hardlink("a", "b"), hardlink("b", "origin"), regularFile("origin", binary)}, []tarEntry{whiteout(".wh.origin")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: []ProducedLayerRange{{Start: 0, End: 1}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Digest).To(gomega.Equal(digestOf(binary)))
		gomega.Expect(produced.Files[0].Classification.Go).To(gomega.Equal(VerdictNames))
	})
})
