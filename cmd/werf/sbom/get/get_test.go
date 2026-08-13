package get

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/image"
)

func TestSbomGet(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sbom Get Suite")
}

var _ = Describe("selectExportedImage", func() {
	newImage := func(name, platform string) *image.Image {
		return &image.Image{Name: name, TargetPlatform: platform}
	}

	BeforeEach(func() {
		commonCmdData.Platform = new([]string)
	})

	It("errors when the image is not found", func() {
		_, err := selectExportedImage([]*image.Image{newImage("other", "")}, "app")

		Expect(err).To(MatchError(ContainSubstring(`unable to find requested image "app"`)))
	})

	It("returns the single match regardless of platform flag", func() {
		img := newImage("app", "linux/amd64")
		found, err := selectExportedImage([]*image.Image{img, newImage("other", "")}, "app")

		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeIdenticalTo(img))
	})

	It("errors listing platforms when multiple matches and no platform given", func() {
		images := []*image.Image{newImage("app", "linux/amd64"), newImage("app", "linux/arm64")}
		_, err := selectExportedImage(images, "app")

		Expect(err).To(MatchError(ContainSubstring("built for multiple platforms")))
		Expect(err).To(MatchError(ContainSubstring("linux/amd64, linux/arm64")))
		Expect(err).To(MatchError(ContainSubstring("--platform")))
	})

	It("selects the matching platform image", func() {
		*commonCmdData.Platform = []string{"linux/arm64"}
		arm64 := newImage("app", "linux/arm64")
		images := []*image.Image{newImage("app", "linux/amd64"), arm64}

		found, err := selectExportedImage(images, "app")

		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeIdenticalTo(arm64))
	})

	It("errors when the requested platform is not built", func() {
		*commonCmdData.Platform = []string{"linux/s390x"}
		images := []*image.Image{newImage("app", "linux/amd64"), newImage("app", "linux/arm64")}

		_, err := selectExportedImage(images, "app")

		Expect(err).To(MatchError(ContainSubstring(`not built for platform "linux/s390x"`)))
	})

	It("rejects multiple platform values", func() {
		*commonCmdData.Platform = []string{"linux/amd64", "linux/arm64"}
		images := []*image.Image{newImage("app", "linux/amd64"), newImage("app", "linux/arm64")}

		_, err := selectExportedImage(images, "app")

		Expect(err).To(MatchError(ContainSubstring("specify exactly one --platform")))
	})
})
