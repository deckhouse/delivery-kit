package nativegate

import (
	"context"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	osPm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

var _ = ginkgo.Describe("instrumented index", func() {
	var img v1.Image
	ginkgo.BeforeEach(func() {
		img = fixtureImage(map[string][]byte{"/index.json": []byte(`[{"name":"data","version":"1","digest":"sha256:` + strings.Repeat("1", 64) + `","arch":["linux/amd64"]}]`)})
	})
	ginkgo.It("requires the instrumented marker even when the digest is pinned", func() {
		_, err := trustedIndexPackages(context.Background(), "registry.example.invalid/packages/index", img)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("instrumented")))
	})
	ginkgo.It("trusts data-only packages by indexed digest and registry", func() {
		img = mutate.Annotations(img, map[string]string{"io.deckhouse.sbom.instrumented": "v1", "io.deckhouse.sbom.base-images-revision": strings.Repeat("a", 40)}).(v1.Image)
		packages, err := trustedIndexPackages(context.Background(), "registry.example.invalid/packages/index", img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(packages).To(gomega.Equal(TrustedPackages{"registry.example.invalid/packages@sha256:" + strings.Repeat("1", 64): osPm.PmPackageInfo{Name: "data", Version: "1", Digest: "sha256:" + strings.Repeat("1", 64), Arch: []string{"linux/amd64"}}}))
	})
})
