package nativegate

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("image source transport", func() {
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
