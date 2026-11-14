package nativegate

import (
	"context"
	"debug/elf"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("bootstrap imports", func() {
	ginkgo.It("rejects bootstrap headers before they can be compiled as declared sources", func() {
		body := []byte("unverified header")
		set := &PackageSet{Originals: []Original{{Path: "/src/vendor.h", SHA256: fixtureDigest(body), Component: fixtureComponent("bootstrap"), Kind: "bootstrap"}}}
		_, err := MaterializeBuildContext(context.Background(), fixtureImage(map[string][]byte{"/src/vendor.h": body}), set, ginkgo.GinkgoT().TempDir(), ContextOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, ContainerRoot: "/.werf/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src/vendor.h"), gomega.ContainSubstring("bootstrap"))))
	})
	ginkgo.DescribeTable("prefers an independent original over bootstrap bytes regardless of order", func(bootstrapFirst bool) {
		body := []byte("source")
		originals := []Original{{Path: "/src/a.c", SHA256: fixtureDigest(body), Component: fixtureComponent("git"), Kind: "git"}, {Path: "/src/a.c", SHA256: fixtureDigest(body), Component: fixtureComponent("bootstrap"), Kind: "bootstrap"}}
		if bootstrapFirst {
			originals[0], originals[1] = originals[1], originals[0]
		}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/a.c": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: originals})).To(gomega.Succeed())
	}, ginkgo.Entry("trusted first", false), ginkgo.Entry("bootstrap first", true))
	ginkgo.It("does not accept bootstrap bytes as an original on their own", func() {
		body := []byte("unverified source")
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/src/input.c": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, Originals: []Original{{Path: "/src/input.c", SHA256: fixtureDigest(body), Component: fixtureComponent("bootstrap"), Kind: "bootstrap"}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src/input.c"), gomega.ContainSubstring("no-data"))))
	})
	ginkgo.It("accepts a bootstrap output carrying its verified composition", func() {
		body := fixtureELF(elf.ET_EXEC, fixtureRecord("c-static", "linux/amd64"))
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/bin/tool": body}), cdx.NewBOM(), VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: []Original{{Path: "/bin/tool", SHA256: fixtureDigest(body), Component: fixtureComponent("bootstrap"), Kind: "bootstrap"}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})
