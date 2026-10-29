package shippedscope

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("Binary attribution of verified binaries", func() {
	const toolPath = "/usr/bin/tool"

	var bom *cdx.BOM
	var verified map[string]string

	binaryOccurrence := func(path, digest string) cdx.EvidenceOccurrence {
		return cdx.EvidenceOccurrence{Location: path, AdditionalContext: binaryEvidencePrefix + digest}
	}

	ginkgo.BeforeEach(func() {
		verified = map[string]string{toolPath: digestOf("tool")}
		bom = cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{
			componentOf("pkg:golang/example.com/guessed@v1.0.0", binaryOccurrence(toolPath, digestOf("tool"))),
			componentOf("pkg:pypi/requests@2.0", cdx.EvidenceOccurrence{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("py")}),
		}
		bom.Dependencies = &[]cdx.Dependency{
			{Ref: "root", Dependencies: lo.ToPtr([]string{"pkg:golang/example.com/guessed@v1.0.0", "pkg:pypi/requests@2.0"})},
		}
	})

	purls := func() []string {
		return lo.Map(lo.FromPtr(bom.Components), func(comp cdx.Component, _ int) string { return comp.PackageURL })
	}

	ginkgo.It("drops a module attributed only to a binary the verification describes", func() {
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, verified)).To(gomega.Equal(1))
		gomega.Expect(purls()).To(gomega.Equal([]string{"pkg:pypi/requests@2.0"}))
		gomega.Expect(lo.FromPtr(lo.FromPtr(bom.Dependencies)[0].Dependencies)).
			To(gomega.Equal([]string{"pkg:pypi/requests@2.0"}), "the dropped component leaves no dangling edge")
	})

	ginkgo.It("keeps a module whose binary holds other content than the verified one", func() {
		verified[toolPath] = digestOf("other")
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, verified)).To(gomega.BeZero())
		gomega.Expect(purls()).To(gomega.ContainElement("pkg:golang/example.com/guessed@v1.0.0"))
	})

	ginkgo.It("keeps a module seen in a binary the verification says nothing about", func() {
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, map[string]string{"/usr/bin/other": digestOf("other")})).To(gomega.BeZero())
		gomega.Expect(purls()).To(gomega.ContainElement("pkg:golang/example.com/guessed@v1.0.0"))
	})

	ginkgo.It("keeps a module whose binary could not be classified", func() {
		(*bom.Components)[0].Evidence.Occurrences = lo.ToPtr([]cdx.EvidenceOccurrence{
			{Location: toolPath, AdditionalContext: binaryEvidencePrefix + "unknown:" + digestOf("tool")},
		})
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, verified)).To(gomega.BeZero())
		gomega.Expect(purls()).To(gomega.ContainElement("pkg:golang/example.com/guessed@v1.0.0"))
	})

	ginkgo.It("keeps a module of an origin whose binary evidence is incomplete", func() {
		addBinaryProperty(&(*bom.Components)[0], propertyBinariesUnknown)
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, verified)).To(gomega.BeZero())
		gomega.Expect(purls()).To(gomega.ContainElement("pkg:golang/example.com/guessed@v1.0.0"))
	})

	ginkgo.It("keeps a module that also has file evidence of its own", func() {
		occurrences := append(lo.FromPtr((*bom.Components)[0].Evidence.Occurrences),
			cdx.EvidenceOccurrence{Location: "/usr/share/go/example.com/go.mod", AdditionalContext: digestOf("go.mod")})
		(*bom.Components)[0].Evidence.Occurrences = &occurrences
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, verified)).To(gomega.BeZero())
		gomega.Expect(purls()).To(gomega.ContainElement("pkg:golang/example.com/guessed@v1.0.0"))
	})

	ginkgo.It("keeps a module seen in a verified binary and in one more the verification does not cover", func() {
		occurrences := append(lo.FromPtr((*bom.Components)[0].Evidence.Occurrences), binaryOccurrence("/opt/helper", digestOf("helper")))
		(*bom.Components)[0].Evidence.Occurrences = &occurrences
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, verified)).To(gomega.BeZero())
		gomega.Expect(purls()).To(gomega.ContainElement("pkg:golang/example.com/guessed@v1.0.0"))
	})

	ginkgo.It("leaves alone what no binary attributes", func() {
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), cyclonedxutil.NewBOM(), verified)).To(gomega.BeZero())
		gomega.Expect(DropBinaryAttributionForVerifiedPaths(context.Background(), bom, nil)).To(gomega.BeZero())
	})
})
