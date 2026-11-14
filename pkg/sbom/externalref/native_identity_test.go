package externalref

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("instrumented source identities", func() {
	ginkgo.DescribeTable("does not send private identities to a public resolver", func(kind string) {
		component := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "internal", Version: "1", PackageURL: "pkg:generic/internal@1?source_kind=" + kind}
		bom := cdx.NewBOM()
		bom.Components = &[]cdx.Component{component}
		resolve := func(context.Context, string) (*ResolveResult, error) {
			return nil, fmt.Errorf("private identity leaked")
		}
		gomega.Expect(NewEnricher(resolve, resolve).Enrich(context.Background(), bom)).To(gomega.Succeed())
	}, ginkgo.Entry("pm", "pm"), ginkgo.Entry("own code", "declared"), ginkgo.Entry("git mapping", "git"))
})
