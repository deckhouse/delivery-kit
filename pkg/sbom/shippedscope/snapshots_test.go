package shippedscope

import (
	"archive/tar"
	"context"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func diffIDsOf(img v1.Image) []v1.Hash {
	config, err := img.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return config.RootFS.DiffIDs
}

var _ v1.Image = (*reconfiguredImage)(nil)

type reconfiguredImage struct {
	v1.Image
	config *v1.ConfigFile
}

func (img *reconfiguredImage) ConfigFile() (*v1.ConfigFile, error) {
	return img.config, nil
}

var _ = ginkgo.Describe("CollectImageSnapshots", func() {
	ginkgo.It("answers what each boundary held, not what the final image holds", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("opt/build/app", "built"), regularFile("etc/conf", "conf")},
			[]tarEntry{whiteout("opt/build/.wh.app")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots[1].Index.Files).To(gomega.HaveKey("/opt/build/app"))
		gomega.Expect(snapshots[1].Index.Files["/opt/build/app"].Digest).To(gomega.Equal(digestOf("built")))
		gomega.Expect(snapshots[2].Index.Files).NotTo(gomega.HaveKey("/opt/build/app"))
		gomega.Expect(snapshots[2].Index.Files).To(gomega.HaveKey("/etc/conf"))
	})

	ginkgo.It("shows the same bytes under the path each boundary spells for them", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("opt/build/app", "moved")},
			[]tarEntry{whiteout("opt/build/.wh.app"), regularFile("usr/bin/app", "moved")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots[1].Index.Files).To(gomega.HaveKey("/opt/build/app"))
		gomega.Expect(snapshots[1].Index.Files).NotTo(gomega.HaveKey("/usr/bin/app"))
		gomega.Expect(snapshots[2].Index.Files).NotTo(gomega.HaveKey("/opt/build/app"))
		gomega.Expect(snapshots[2].Index.Files["/usr/bin/app"].Digest).To(gomega.Equal(digestOf("moved")))
	})

	ginkgo.It("keeps a path a later boundary holds unchanged", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("etc/conf", "same")},
			[]tarEntry{regularFile("etc/other", "other")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{CapturePaths: []string{"/etc/conf"}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots[1].Index.Files["/etc/conf"].Digest).To(gomega.Equal(digestOf("same")))
		gomega.Expect(snapshots[2].Index.Files["/etc/conf"].Digest).To(gomega.Equal(digestOf("same")))
		gomega.Expect(snapshots[2].Bodies).To(gomega.HaveKeyWithValue("/etc/conf", []byte("same")))
	})

	ginkgo.It("captures the bytes an earlier boundary held of a path the final image overwrites", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("var/lib/pm/receipt.json", "early")},
			[]tarEntry{regularFile("var/lib/pm/receipt.json", "late")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{CapturePaths: []string{"/var/lib/pm/receipt.json"}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots[1].Bodies).To(gomega.HaveKeyWithValue("/var/lib/pm/receipt.json", []byte("early")))
		gomega.Expect(snapshots[2].Bodies).To(gomega.HaveKeyWithValue("/var/lib/pm/receipt.json", []byte("late")))
	})

	ginkgo.It("captures the bytes an earlier boundary held of a path the final image deletes", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("var/lib/pm/receipt.json", "early")},
			[]tarEntry{whiteout("var/lib/pm/.wh.receipt.json")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{CapturePaths: []string{"/var/lib/pm/receipt.json"}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots[1].Bodies).To(gomega.HaveKeyWithValue("/var/lib/pm/receipt.json", []byte("early")))
		gomega.Expect(snapshots[2].Bodies).To(gomega.BeEmpty())
		gomega.Expect(snapshots[2].Index.Files).NotTo(gomega.HaveKey("/var/lib/pm/receipt.json"))
	})

	ginkgo.It("keeps no bytes beyond the paths the caller asked for", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("var/lib/pm/receipt.json", "asked"),
			regularFile("usr/bin/tool", "unasked"),
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1}, CollectImageSnapshotsOptions{CapturePaths: []string{"/var/lib/pm/receipt.json"}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots[1].Index.Files).To(gomega.HaveKey("/usr/bin/tool"))
		gomega.Expect(snapshots[1].Bodies).To(gomega.HaveLen(1))
		gomega.Expect(snapshots[1].Bodies).To(gomega.HaveKey("/var/lib/pm/receipt.json"))
	})

	ginkgo.It("reads a repeated boundary once and answers the empty filesystem for boundary zero", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{0, 1, 1, 0}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(snapshots).To(gomega.HaveLen(2))
		gomega.Expect(snapshots[0].Index.Files).To(gomega.BeEmpty())
		gomega.Expect(snapshots[0].Index.Symlinks).To(gomega.BeEmpty())
		gomega.Expect(snapshots[0].Index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(snapshots[0].Bodies).To(gomega.BeEmpty())
		gomega.Expect(snapshots[1].Index.Files).To(gomega.HaveKey("/etc/conf"))
	})

	ginkgo.It("refuses an image whose layers are not the ones the boundaries were drawn from", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		other, err := imageOf([]tarEntry{regularFile("etc/conf", "elsewhere")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(other), []int{1}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("do not match the 1 expected stage layers")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.It("refuses an image whose config declares fewer layers than it holds", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")}, []tarEntry{regularFile("etc/other", "other")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		config, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		truncated := config.DeepCopy()
		truncated.RootFS.DiffIDs = truncated.RootFS.DiffIDs[:1]

		snapshots, err := CollectImageSnapshots(ctx, &reconfiguredImage{Image: img, config: truncated}, truncated.RootFS.DiffIDs, []int{1}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("declares 1 layers while the image holds 2")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.It("refuses an image without a config", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, &reconfiguredImage{Image: img}, nil, []int{1}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("empty config")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.DescribeTable("refuses a boundary the image cannot answer", func(ctx ginkgo.SpecContext, boundaries []int) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), boundaries, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("for image with 1 layers")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	},
		ginkgo.Entry("negative", []int{-1}),
		ginkgo.Entry("past the last layer", []int{2}),
		ginkgo.Entry("invalid beside a valid one", []int{1, 2}),
	)

	ginkgo.It("refuses a capture path that is not rooted", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1}, CollectImageSnapshotsOptions{CapturePaths: []string{"etc/conf"}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not rooted")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.It("refuses a boundary whose index needs hardlink fallback instead of reporting absence", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("bin/busybox", "shared")},
			[]tarEntry{hardlink("bin/sh", "bin/busybox")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("boundary 2 needs hardlink fallback")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.It("reports a layer it cannot read instead of returning the boundaries it managed", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("etc/conf", "conf")},
			[]tarEntry{{name: "../escape", typeflag: tar.TypeReg, body: "escaped"}},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		snapshots, err := CollectImageSnapshots(ctx, img, diffIDsOf(img), []int{1, 2}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsafe tar path")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.It("stops when the context is canceled", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("etc/conf", "conf")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		canceled, cancel := context.WithCancel(ctx)
		cancel()

		snapshots, err := CollectImageSnapshots(canceled, img, diffIDsOf(img), []int{1}, CollectImageSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(context.Canceled))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})
})
