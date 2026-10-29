package shippedscope

import (
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("File index directory facts", func() {
	ginkgo.It("records empty and implicit directories without treating a symlink as a directory", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{directory("empty"), regularFile("usr/lib/x", "x"), symlink("lib", "usr/lib")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Directories).To(gomega.HaveKey("/"))
		gomega.Expect(index.Directories).To(gomega.HaveKey("/empty"))
		gomega.Expect(index.Directories).To(gomega.HaveKey("/usr"))
		gomega.Expect(index.Directories).To(gomega.HaveKey("/usr/lib"))
		gomega.Expect(index.Directories).NotTo(gomega.HaveKey("/lib"))
		gomega.Expect(index.Directories).NotTo(gomega.HaveKey("/usr/lib/x"))
	})

	ginkgo.It("records the root of an empty image", func(ctx ginkgo.SpecContext) {
		index, err := IndexImageFiles(ctx, empty.Image)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Directories).To(gomega.HaveLen(1))
		gomega.Expect(index.Directories).To(gomega.HaveKey("/"))
	})

	ginkgo.It("does not resurrect a whiteouted directory", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{directory("gone"), regularFile("gone/x", "x")}, []tarEntry{whiteout(".wh.gone")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Directories).NotTo(gomega.HaveKey("/gone"))
		gomega.Expect(index.Files).NotTo(gomega.HaveKey("/gone/x"))
	})
})
