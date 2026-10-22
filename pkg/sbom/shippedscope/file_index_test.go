package shippedscope

import (
	"archive/tar"
	"context"
	"fmt"
	"time"

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

	It("keeps a hardlink on the content of its own layer when a later layer rewrites the target", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("bin/busybox", "old"), hardlink("bin/sh", "bin/busybox")},
			[]tarEntry{regularFile("bin/busybox", "new")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/bin/busybox"].Digest).To(Equal(digestOf("new")))
		Expect(index.Files["/bin/sh"].Digest).To(Equal(digestOf("old")))
	})

	It("keeps a hardlink on its own layer when the link entry precedes its target in the layer", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{hardlink("bin/sh", "bin/busybox"), regularFile("bin/busybox", "old")},
			[]tarEntry{regularFile("bin/busybox", "new")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/bin/sh"].Digest).To(Equal(digestOf("old")))
	})

	It("keeps a hardlink to a symlink on the target its own layer spells", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{symlink("bin/sh", "/bin/dash"), hardlink("bin/rsh", "bin/sh")},
			[]tarEntry{symlink("bin/sh", "/bin/bash")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Symlinks["/bin/sh"]).To(Equal("/bin/bash"))
		Expect(index.Symlinks["/bin/rsh"]).To(Equal("/bin/dash"))
	})

	It("takes the topmost hardlink when both layers link the same path to the same target", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("bin/busybox", "old"), hardlink("bin/sh", "bin/busybox")},
			[]tarEntry{regularFile("bin/busybox", "new"), hardlink("bin/sh", "bin/busybox")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/bin/sh"].Digest).To(Equal(digestOf("new")))
	})

	It("does not let a lower layer answer for a hardlink a higher layer owns", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{
				regularFile("bin/busybox", "old"),
				hardlink("bin/sh", "bin/busybox"),
				hardlink("bin/awk", "bin/busybox"),
			},
			[]tarEntry{regularFile("bin/busybox", "new")},
			[]tarEntry{hardlink("bin/sh", "bin/busybox")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/bin/awk"].Digest).To(Equal(digestOf("old")))
		Expect(index.Files["/bin/sh"].Digest).To(Equal(digestOf("new")))
	})

	It("falls back to the flattened view for a hardlink whose own layer lacks the target", func(ctx SpecContext) {
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

	It("keeps the topmost layer when two layers spell the same path differently", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("usr/bin/x", "bottom")},
			[]tarEntry{regularFile("/usr/bin/x", "top")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/usr/bin/x"].Digest).To(Equal(digestOf("top")))
	})

	It("roots a path a layer spells relative to the archive", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("./usr/bin/dotted", "body")})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(HaveKey("/usr/bin/dotted"))
	})

	It("follows a chain of hardlinks to the content at its end", func(ctx SpecContext) {
		entries := []tarEntry{regularFile("usr/bin/origin", "shared")}
		for i := range 6 {
			target := fmt.Sprintf("usr/bin/link%d", i+1)
			if i == 5 {
				target = "usr/bin/origin"
			}
			entries = append(entries, hardlink(fmt.Sprintf("usr/bin/link%d", i), target))
		}

		img, err := imageOf(entries)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Incomplete).To(BeFalse())
		for i := range 6 {
			Expect(index.Files[fmt.Sprintf("/usr/bin/link%d", i)].Digest).To(Equal(digestOf("shared")))
		}
	})

	It("resolves a hardlink whose target the layer spells relative to the archive", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/origin", "shared"),
			hardlink("usr/bin/alias", "./usr/bin/origin"),
		})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files["/usr/bin/alias"].Digest).To(Equal(digestOf("shared")))
	})

	It("records a hardlink to a symlink as a symlink", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			symlink("usr/bin/link", "/usr/bin/target"),
			hardlink("usr/bin/alias", "usr/bin/link"),
		})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Symlinks).To(HaveKeyWithValue("/usr/bin/alias", "/usr/bin/target"))
		Expect(index.Files).NotTo(HaveKey("/usr/bin/alias"))
	})

	It("keeps directories out of the file index", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{directory("opt/app"), regularFile("opt/app/file", "body")})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(HaveKey("/opt/app/file"))
		Expect(index.Files).NotTo(HaveKey("/opt/app"))
	})

	It("keeps a hardlink whose target a later layer whited out, since its own layer holds the bytes", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("usr/bin/origin", "shared"), hardlink("usr/bin/alias", "usr/bin/origin")},
			[]tarEntry{whiteout("usr/bin/.wh.origin")},
		)
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).NotTo(HaveKey("/usr/bin/origin"))
		Expect(index.Files["/usr/bin/alias"].Digest).To(Equal(digestOf("shared")))
	})

	It("leaves a hardlink no layer can resolve out of the index instead of failing", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{hardlink("usr/bin/alias", "usr/bin/absent")})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(BeEmpty())
		Expect(index.Incomplete).To(BeTrue(), "unresolved hardlinks mark the index incomplete")
	})

	It("gives up on hardlinks that point at each other", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			hardlink("usr/bin/first", "usr/bin/second"),
			hardlink("usr/bin/second", "usr/bin/first"),
		})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(BeEmpty())
		Expect(index.Incomplete).To(BeTrue(), "circular hardlinks mark the index incomplete")
	}, SpecTimeout(time.Minute))

	It("reports an image it cannot read instead of returning a partial index", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/good", "good"),
			{name: "../escape", typeflag: tar.TypeReg, body: "escaped"},
		})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).To(MatchError(ContainSubstring("unsafe tar path")))
		Expect(index).To(BeNil())
	})

	It("stops when the context is canceled", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("usr/bin/tool", "payload")})
		Expect(err).NotTo(HaveOccurred())

		canceled, cancel := context.WithCancel(ctx)
		cancel()

		_, err = IndexImageFiles(canceled, img)
		Expect(err).To(MatchError(context.Canceled))
	})

	It("returns an empty index for an image without layers", func(ctx SpecContext) {
		img, err := imageOf()
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(BeEmpty())
		Expect(index.Symlinks).To(BeEmpty())
		Expect(index.Incomplete).To(BeFalse())
	})

	It("marks the index complete when all hardlinks resolve", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/origin", "shared"),
			hardlink("usr/bin/alias", "usr/bin/origin"),
		})
		Expect(err).NotTo(HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(index.Files).To(HaveKey("/usr/bin/origin"))
		Expect(index.Files).To(HaveKey("/usr/bin/alias"))
		Expect(index.Incomplete).To(BeFalse())
	})
})
