package build

import (
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("producer asset declarations", func() {
	declaration := func(assets string) []byte {
		return []byte(`{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}],"goEmbed":` + assets + `}}}`)
	}
	binding := `{"sourceImage":"ui","sourceRoot":"/ui/dist","targetRoot":"/build/ui/dist","proofPath":"/.werf/assets/ui.json"}`

	ginkgo.It("keeps an explicit root obligation independently of any asset list", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + binding + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].GoEmbed).To(gomega.HaveLen(1))
		gomega.Expect(parsed.Stages["install"].GoEmbed[0].TargetRoot).To(gomega.Equal("/build/ui/dist"))
	})

	ginkgo.DescribeTable("refuses ambiguous or incomplete asset intent", func(assets string) {
		_, err := parseSBOMBuildContextDeclaration(declaration(assets))
		gomega.Expect(err).To(gomega.HaveOccurred())
	},
		ginkgo.Entry("null", "null"),
		ginkgo.Entry("not an array", binding),
		ginkgo.Entry("missing source handle", `[{}]`),
		ginkgo.Entry("relative source root", "["+strings.Replace(binding, `"/ui/dist"`, `"ui/dist"`, 1)+"]"),
		ginkgo.Entry("unclean target root", "["+strings.Replace(binding, `"/build/ui/dist"`, `"/build/../dist"`, 1)+"]"),
		ginkgo.Entry("relative proof file", "["+strings.Replace(binding, `"/.werf/assets/ui.json"`, `"proof.json"`, 1)+"]"),
		ginkgo.Entry("duplicate member", "["+strings.Replace(binding, `"sourceImage":"ui"`, `"sourceImage":"ui","sourceImage":"other"`, 1)+"]"),
		ginkgo.Entry("unknown member", "["+strings.Replace(binding, `"sourceImage":"ui"`, `"sourceImage":"ui","extra":true`, 1)+"]"),
	)

	ginkgo.It("allows an explicit empty extension without creating an obligation", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].GoEmbed).To(gomega.BeEmpty())
	})
})
