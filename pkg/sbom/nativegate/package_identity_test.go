package nativegate

import (
	"context"
	"encoding/json"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("indexed package identity", func() {
	ginkgo.It("verifies package symlink targets before compilation and publication", func(ctx ginkgo.SpecContext) {
		source, trusted := fixtureRegistryPackage(ctx)
		set, err := OpenPackageSet(ctx, &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}}, "linux/amd64", trusted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(set.Symlinks).To(gomega.Equal(map[string]string{"/usr/share/current": "data"}))
		opts := VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: set.Originals, ExpectedSymlinks: set.Symlinks, TrustedComponents: set.Components}
		unchanged := fixtureImageWithLinks(map[string][]byte{"/usr/share/data": []byte("original")}, map[string]string{"/usr/share/current": "data"})
		gomega.Expect(Verify(ctx, unchanged, cdx.NewBOM(), opts)).To(gomega.Succeed())
		changed := fixtureImageWithLinks(map[string][]byte{"/usr/share/data": []byte("original")}, map[string]string{"/usr/share/current": "missing"})
		gomega.Expect(Verify(ctx, changed, cdx.NewBOM(), opts)).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/usr/share/current"), gomega.ContainSubstring("hash-mismatch"))))
		_, err = MaterializeBuildContext(context.Background(), changed, set, ginkgo.GinkgoT().TempDir(), ContextOptions{Subject: "app", Platform: "linux/amd64", ContainerRoot: "/.werf/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/usr/share/current")))
	})
	ginkgo.It("uses the pinned package and rejects a forged receipt version", func(ctx ginkgo.SpecContext) {
		source, trusted := fixtureRegistryPackage(ctx)
		receipt := &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}}
		set, err := OpenPackageSet(ctx, receipt, "linux/amd64", trusted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(set.Originals).To(gomega.HaveLen(1))
		gomega.Expect(set.Components[0].Version).To(gomega.Equal("1"))
		packet, err := readSourcePackage(source)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		packet.Version = "forged"
		receipt.Sources[0].Packet, err = json.Marshal(packet)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = OpenPackageSet(ctx, receipt, "linux/amd64", trusted)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("identity contradicts instrumented index")))
	})
})
