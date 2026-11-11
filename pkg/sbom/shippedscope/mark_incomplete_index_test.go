package shippedscope

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("MarkNotShipped on an image indexed through the hardlink fallback", func() {
	const donorBytes = "donor bytes"

	var bom *cdx.BOM

	ginkgo.BeforeEach(func() {
		bom = &cdx.BOM{Components: &[]cdx.Component{
			componentOf("pkg:pypi/donated@1.0.0", cdx.EvidenceOccurrence{Location: "/donor/donated.py", AdditionalContext: digestOf(donorBytes)}),
			componentOf("pkg:golang/example.com/gone@v1.0.0", cdx.EvidenceOccurrence{Location: "/dist/gone", AdditionalContext: binaryEvidencePrefix + digestOf("gone")}),
		}}
	})

	judge := func(ctx ginkgo.SpecContext, filesets *Filesets) {
		RecordOccurrences(ctx, bom, filesets.Filesets)
		MarkNotShipped(ctx, bom, filesets)
	}

	ginkgo.It("withholds a not-shipped verdict when a hardlink may still hold the component's bytes", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx,
			[]tarEntry{regularFile("srv/blob", donorBytes)},
			[]tarEntry{hardlink("srv/alias", "srv/blob")},
			[]tarEntry{whiteout("srv/.wh.blob")},
			[]tarEntry{regularFile("srv/blob", "replacement")},
		)
		gomega.Expect(filesets.Index.Incomplete).To(gomega.BeTrue(), "the alias resolves against the flattened view")
		gomega.Expect(filesets.Index.Files["/srv/alias"].Digest).To(gomega.Equal(digestOf("replacement")))

		judge(ctx, filesets)

		gomega.Expect(isShipped((*bom.Components)[0])).To(gomega.BeTrue())
		gomega.Expect(isShipped((*bom.Components)[1])).To(gomega.BeTrue())
	})

	ginkgo.It("still marks components whose files a complete index does not hold", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx, []tarEntry{regularFile("srv/blob", "replacement")})
		gomega.Expect(filesets.Index.Incomplete).To(gomega.BeFalse())

		judge(ctx, filesets)

		gomega.Expect(isShipped((*bom.Components)[0])).To(gomega.BeFalse())
		gomega.Expect(isShipped((*bom.Components)[1])).To(gomega.BeFalse())
	})
})
