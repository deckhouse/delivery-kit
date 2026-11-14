package build

import (
	"context"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	buildimage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

var _ = ginkgo.Describe("native SBOM cache", func() {
	ginkgo.It("invalidates only the SBOM artifact when GOST settings change", func() {
		first := nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueNo})
		gomega.Expect(nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueNo})).To(gomega.Equal(first))
		gomega.Expect(nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueNo, SecurityFunction: gost.GostValueNo})).NotTo(gomega.Equal(first))
		gomega.Expect(nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes})).NotTo(gomega.Equal(first))
	})
	ginkgo.It("needs no intermediate ancestry when an image imports nothing", func() {
		phase := &BuildPhase{}
		result, err := phase.nativeImportOriginals(context.Background(), &buildimage.Image{}, empty.Image, &image.StageDesc{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.Originals).To(gomega.BeEmpty())
	})
})
