package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IndexImageFiles", func() {
	It("indexes regular files by rooted path with their content digest and size", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("usr/bin/tool", "payload")})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(HaveKeyWithValue("/usr/bin/tool", File{
			Digest: digestOf("payload"),
			Size:   int64(len("payload")),
		}))
	})

	It("keeps the content of the topmost layer when a later layer overwrites a file", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("etc/conf", "old")},
			[]tarEntry{regularFile("etc/conf", "new")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/etc/conf"].Digest).To(Equal(digestOf("new")))
	})

	It("drops a file a later layer whites out", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("usr/lib/kept.so", "kept"), regularFile("usr/lib/gone.so", "gone")},
			[]tarEntry{whiteout("usr/lib/.wh.gone.so")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(HaveKey("/usr/lib/kept.so"))
		Expect(index.Files).NotTo(HaveKey("/usr/lib/gone.so"))
	})

	It("hides lower-layer entries of an opaque directory while keeping those of the opaquing layer", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("opt/app/lower.txt", "lower"), regularFile("opt/keep.txt", "keep")},
			[]tarEntry{
				directory("opt/app"),
				whiteout("opt/app/.wh..wh..opq"),
				regularFile("opt/app/upper.txt", "upper"),
			},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).NotTo(HaveKey("/opt/app/lower.txt"))
		Expect(index.Files).To(HaveKey("/opt/app/upper.txt"))
		Expect(index.Files).To(HaveKey("/opt/keep.txt"))
	})

	It("gives a hardlink the digest of its target, including across layers", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("usr/bin/origin", "shared")},
			[]tarEntry{hardlink("usr/bin/alias", "usr/bin/origin")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/usr/bin/alias"]).To(Equal(index.Files["/usr/bin/origin"]))
		Expect(index.Files["/usr/bin/alias"].Digest).To(Equal(digestOf("shared")))
	})

	It("records symlinks with their raw target and keeps them out of the file index", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/libc.so.6", "libc"),
			symlink("lib/libc.so", "../usr/lib/libc.so.6"),
		})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Symlinks).To(HaveKeyWithValue("/lib/libc.so", "../usr/lib/libc.so.6"))
		Expect(index.Files).NotTo(HaveKey("/lib/libc.so"))
	})

	It("indexes an empty file so the rule can tell it apart from a missing one", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("usr/lib/python/py.typed", "")})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(HaveKeyWithValue("/usr/lib/python/py.typed", File{
			Digest: digestOf(""),
			Size:   0,
		}))
	})

	It("returns an empty index for an image without layers", func(ctx SpecContext) {
		img, err := imageOf()
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(BeEmpty())
		Expect(index.Symlinks).To(BeEmpty())
	})
})
