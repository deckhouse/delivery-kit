package nativegate

import (
	"encoding/json"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Source Packet identity adapter", func() {
	ginkgo.It("reuses the pm metadata decoder without rewriting opaque Packet fields", func() {
		source := sources.Source{Packet: json.RawMessage(`{"name":"x","version":"1","digest":"sha256:` + strings.Repeat("a", 64) + `","arch":["linux/amd64"],"license":"MIT","opaque":9007199254740993}`)}
		before := slices.Clone(source.Packet)
		pkg, err := readSourcePackage(source)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(pkg.Name).To(gomega.Equal("x"))
		gomega.Expect(pkg.Version).To(gomega.Equal("1"))
		gomega.Expect(pkg.Digest).To(gomega.Equal("sha256:" + strings.Repeat("a", 64)))
		gomega.Expect(pkg.Arch).To(gomega.Equal([]string{"linux/amd64"}))
		gomega.Expect(pkg.License).To(gomega.Equal("MIT"))
		gomega.Expect(source.Packet).To(gomega.Equal(before))
	})

	ginkgo.DescribeTable("does not infer declared architectures from other keys", func(body string) {
		pkg, err := readSourcePackage(sources.Source{Packet: json.RawMessage(body)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(pkg.Arch).To(gomega.BeEmpty())
	},
		ginkgo.Entry("absent", `{"name":"x"}`),
		ginkgo.Entry("null", `{"name":"x","arch":null}`),
		ginkgo.Entry("empty", `{"name":"x","arch":[]}`),
		ginkgo.Entry("case-folded key", `{"name":"x","Arch":["linux/amd64"]}`),
	)

	ginkgo.It("uses only the exact arch value even beside a differently cased key", func() {
		pkg, err := readSourcePackage(sources.Source{Packet: json.RawMessage(`{"arch":["linux/amd64"],"Arch":["linux/arm64"]}`)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(pkg.Arch).To(gomega.Equal([]string{"linux/amd64"}))
	})

	ginkgo.DescribeTable("propagates malformed Packet identity", func(body string) {
		_, err := readSourcePackage(sources.Source{Packet: json.RawMessage(body)})
		gomega.Expect(err).To(gomega.HaveOccurred())
	},
		ginkgo.Entry("malformed", `{`),
		ginkgo.Entry("array", `[]`),
		ginkgo.Entry("arch is a scalar", `{"arch":"linux/amd64"}`),
		ginkgo.Entry("arch contains numbers", `{"arch":[1]}`),
	)
})
