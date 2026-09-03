package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/image"
	imagePkg "github.com/werf/werf/v2/pkg/image"
)

var _ = Describe("artifact subjects", func() {
	newImage := func(name, platform, digest string) *image.Image {
		img := &image.Image{Name: name, TargetPlatform: platform}
		img.SetContentTagDesc(&imagePkg.StageDesc{
			StageID: imagePkg.NewStageID(digest, 1),
			Info:    &imagePkg.Info{Repository: "primary", RepoDigest: "primary@" + digest},
		})
		return img
	}

	It("selects the matching platform manifest for a multi-platform SBOM", func() {
		images := []*image.Image{
			newImage("app", "linux/amd64", "sha256:amd64"),
			newImage("app", "linux/arm64", "sha256:arm64"),
		}
		multiImage := image.NewMultiplatformImage("app", images, 0, 1)
		multiImage.SetFinalStageDesc(&imagePkg.StageDesc{
			Info: &imagePkg.Info{
				IsIndex: true,
				Index: []*imagePkg.Info{
					{Repository: "final", RepoDigest: "final@sha256:amd64"},
					{Repository: "final", RepoDigest: "final@sha256:arm64"},
				},
			},
		})
		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		tree.SetMultiplatformImage(multiImage)
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: tree}}}

		descriptor := finalStageDescForPlatform(phase, "app", images, "linux/arm64")

		Expect(descriptor).NotTo(BeNil())
		Expect(descriptor.Info.GetDigest()).To(Equal("sha256:arm64"))
	})

	It("selects a platform manifest by platform metadata regardless of index order", func() {
		images := []*image.Image{
			newImage("app", "linux/amd64", "sha256:amd64"),
			newImage("app", "linux/arm64", "sha256:arm64"),
		}
		multiImage := image.NewMultiplatformImage("app", images, 0, 1)
		multiImage.SetFinalStageDesc(&imagePkg.StageDesc{Info: &imagePkg.Info{
			IsIndex: true,
			Index: []*imagePkg.Info{
				{Platform: "linux/arm64", RepoDigest: "final@sha256:arm64"},
				{Platform: "linux/amd64", RepoDigest: "final@sha256:amd64"},
			},
		}})
		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		tree.SetMultiplatformImage(multiImage)
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: tree}}}

		descriptor := finalStageDescForPlatform(phase, "app", images, "linux/amd64")

		Expect(descriptor).NotTo(BeNil())
		Expect(descriptor.Info.GetDigest()).To(Equal("sha256:amd64"))
	})

	It("keeps the top-level index as the VEX subject for a multi-platform image", func() {
		images := []*image.Image{
			newImage("app", "linux/amd64", "sha256:amd64"),
			newImage("app", "linux/arm64", "sha256:arm64"),
		}
		multiImage := image.NewMultiplatformImage("app", images, 0, 1)
		index := &imagePkg.StageDesc{Info: &imagePkg.Info{
			IsIndex:    true,
			Repository: "final",
			RepoDigest: "final@sha256:index",
			Index:      []*imagePkg.Info{{RepoDigest: "final@sha256:amd64"}, {RepoDigest: "final@sha256:arm64"}},
		}}
		multiImage.SetFinalStageDesc(index)
		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		tree.SetMultiplatformImage(multiImage)
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: tree}}}

		descriptor := finalStageDescForImage(phase, "app", images)

		Expect(descriptor).To(BeIdenticalTo(index))
		Expect(descriptor.Info.GetDigest()).To(Equal("sha256:index"))
	})

	It("uses no platform annotation for a multi-platform VEX artifact", func() {
		images := []*image.Image{
			{TargetPlatform: "linux/amd64"},
			{TargetPlatform: "linux/arm64"},
		}

		Expect(vexTargetPlatform(images)).To(BeEmpty())
	})

	It("uses the manifest platform for a single-platform VEX artifact", func() {
		Expect(vexTargetPlatform([]*image.Image{{TargetPlatform: "linux/amd64"}})).To(Equal("linux/amd64"))
	})

	It("returns no final subject when a multi-platform tree is unavailable", func() {
		images := []*image.Image{newImage("app", "linux/amd64", "sha256:amd64"), newImage("app", "linux/arm64", "sha256:arm64")}
		phase := &BuildPhase{}

		Expect(finalStageDescForImage(phase, "app", images)).To(BeNil())
	})

	It("uses the published manifest as the final subject for a single-platform image", func() {
		images := []*image.Image{newImage("app", "linux/amd64", "sha256:amd64")}
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{}}}

		descriptor := finalStageDescForPlatform(phase, "app", images, "linux/amd64")

		Expect(descriptor).To(BeIdenticalTo(images[0].GetContentTagDesc()))
		Expect(descriptor.Info.GetDigest()).To(Equal("sha256:amd64"))
	})
})
