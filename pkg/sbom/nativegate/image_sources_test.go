package nativegate

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("image source transport", func() {
	ginkgo.It("imports a generated file to the root outside destination ownRoots", func(ctx ginkgo.SpecContext) {
		body := []byte(`{"image":"sha256:example"}`)
		source := fixtureImage(map[string][]byte{"/src/images_digests.json": body})
		roots, err := UserSourceRoots(ctx, []string{}, "/src", "/tmp")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bom := cdx.NewBOM()
		gomega.Expect(Verify(ctx, source, bom, VerifyOptions{Subject: "generated-source", Platform: "linux/amd64", UserRoots: roots})).To(gomega.Succeed())
		originals, err := ImageOriginals(ctx, bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		sourceIndex, err := shippedscope.IndexImageFiles(ctx, source)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		before, err := shippedscope.IndexImageFiles(ctx, fixtureImage(nil))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		destination := fixtureImage(map[string][]byte{"/images_digests.json": body})
		after, err := shippedscope.IndexImageFiles(ctx, destination)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		projected, err := ProjectImageOriginals(ctx, originals, sourceIndex, before, after, ImportScope{FromPath: "/src/images_digests.json", ToPath: "/images_digests.json"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		result := cdx.NewBOM()
		gomega.Expect(Verify(ctx, destination, result, VerifyOptions{Subject: "final", Platform: "linux/amd64", Originals: projected, TrustedComponents: *bom.Components})).To(gomega.Succeed())
		gomega.Expect(*result.Components).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "/images_digests.json"), gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "image"}))))))
	})
	ginkgo.It("round trips source file ownership through standard CycloneDX fields", func() {
		bom := cdx.NewBOM()
		opts := VerifyOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, Originals: []Original{{Path: "/src/a.c", SHA256: fixtureDigest([]byte("source")), Component: fixtureComponent("git"), Kind: "git"}}}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/a.c": []byte("source")}), bom, opts)).To(gomega.Succeed())
		originals, err := ImageOriginals(context.Background(), bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.BOMRef).To(gomega.Equal("git"))
		gomega.Expect(originals[0].SHA256).To(gomega.Equal(fixtureDigest([]byte("source"))))
	})
})
