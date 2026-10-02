package buildah

import (
	"context"
	"errors"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/opstats"
)

type failingReader struct{}

func (r failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("read failed")
}

var _ = Describe("NativeBuildah operation stats", func() {
	// Every call below fails while resolving its arguments, before the containers storage is
	// touched, so the observation is the only thing being exercised here.
	const invalidPlatform = "bad platform"

	DescribeTable("records exactly one operation for a failed call",
		func(expectedOp opstats.Operation, call func(ctx context.Context, b *NativeBuildah) error) {
			collector := opstats.NewCollector()
			ctx := opstats.NewContext(context.Background(), collector)

			Expect(call(ctx, &NativeBuildah{})).To(HaveOccurred())

			summary := collector.Summary()
			Expect(summary).To(HaveLen(1))
			Expect(summary[0].Operation).To(Equal(expectedOp))
			Expect(summary[0].Count).To(Equal(1))
		},
		Entry("BuildFromDockerfile", opstats.Operation("buildah: build"), func(ctx context.Context, b *NativeBuildah) error {
			_, err := b.BuildFromDockerfile(ctx, "Dockerfile", BuildFromDockerfileOpts{CommonOpts: CommonOpts{TargetPlatform: invalidPlatform}})
			return err
		}),
		Entry("FromCommand", opstats.Operation("buildah: container create"), func(ctx context.Context, b *NativeBuildah) error {
			_, err := b.FromCommand(ctx, "container", "image", FromCommandOpts{TargetPlatform: invalidPlatform})
			return err
		}),
		Entry("Pull", opstats.Operation("buildah: image pull"), func(ctx context.Context, b *NativeBuildah) error {
			_, err := b.Pull(ctx, "image", PullOpts{TargetPlatform: invalidPlatform})
			return err
		}),
		Entry("Tag", opstats.Operation("buildah: image tag"), func(ctx context.Context, b *NativeBuildah) error {
			return b.Tag(ctx, "image", "newImage", TagOpts{TargetPlatform: invalidPlatform})
		}),
		Entry("Rmi", opstats.Operation("buildah: image remove"), func(ctx context.Context, b *NativeBuildah) error {
			return b.Rmi(ctx, "image", RmiOpts{CommonOpts: CommonOpts{TargetPlatform: invalidPlatform}})
		}),
		Entry("PruneImages", opstats.Operation("buildah: image prune"), func(ctx context.Context, b *NativeBuildah) error {
			_, err := b.PruneImages(ctx, PruneImagesOptions{CommonOpts: CommonOpts{TargetPlatform: invalidPlatform}})
			return err
		}),
		Entry("Images", opstats.Operation("buildah: image list"), func(ctx context.Context, b *NativeBuildah) error {
			_, err := b.Images(ctx, ImagesOptions{CommitOpts: CommitOpts{CommonOpts: CommonOpts{TargetPlatform: invalidPlatform}}})
			return err
		}),
		Entry("LoadImageFromStream", opstats.Operation("buildah: image load"), func(ctx context.Context, b *NativeBuildah) error {
			_, err := b.LoadImageFromStream(ctx, io.Reader(failingReader{}))
			return err
		}),
	)
})
