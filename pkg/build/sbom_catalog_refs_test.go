package build

import (
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

// These ask of the translation what a whole convergence cannot: a catalog that names a
// component nobody declares, and a document holding one component under two refs. Neither
// arises from the pipeline as it stands, and both would be a hole in what is published.
var _ = Describe("Translating a verified catalog onto the document that is published", func() {
	proven := cdx.Component{
		Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1",
		BOMRef: "urn:dk:component:sha256:aaaa", PackageURL: "pkg:generic/app@1",
	}

	documentWith := func(catalog string, components ...cdx.Component) (*cdx.BOM, *cdx.BOM) {
		published := &cdx.BOM{
			Metadata:   &cdx.Metadata{Properties: &[]cdx.Property{{Name: catalogProperty, Value: catalog}}},
			Components: lo.ToPtr(components),
		}
		verified := &cdx.BOM{Components: &[]cdx.Component{proven}}

		return published, verified
	}

	It("refuses a catalog naming a component the verification never declared", func() {
		catalog := `{"schema":"dk.catalog/v4","records":[{"path":"/app","sha256":"sha256:00","origin":"build","components":["urn:dk:component:sha256:ffff"]}],"components":{}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})

		err := rewriteCatalogRefs(published, verified)

		Expect(err).To(MatchError(ContainSubstring("/app: the published document holds no component for urn:dk:component:sha256:ffff")))
	})

	It("refuses to publish when a component the verification proved is gone from the document", func() {
		catalog := `{"schema":"dk.catalog/v4","records":[],"components":{}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "other", Version: "9", BOMRef: "derived", PackageURL: "pkg:generic/other@9",
		})

		err := rewriteCatalogRefs(published, verified)

		Expect(err).To(MatchError(ContainSubstring(
			"invalid: the published document holds no component the verification proved: urn:dk:component:sha256:aaaa")))
	})

	// A document may hold one component in more than one place - among its own
	// components and again under the image it describes. The translation must settle on
	// one of them, and on the same one every time, or two records naming one component
	// would point at two different refs.
	It("settles on the ref the document declares first", func() {
		catalog := `{"schema":"dk.catalog/v4","records":[{"path":"/app","sha256":"sha256:00","origin":"build",` +
			`"components":["urn:dk:component:sha256:aaaa"],"owners":["urn:dk:component:sha256:aaaa"]},` +
			`{"path":"/app2","sha256":"sha256:01","origin":"build","components":["urn:dk:component:sha256:aaaa"]}],` +
			`"components":{"urn:dk:component:sha256:aaaa":{"type":"library","name":"app"}}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "first", PackageURL: "pkg:generic/app@1",
		})
		published.Metadata.Component = &cdx.Component{
			Type: cdx.ComponentTypeContainer, Name: "image", BOMRef: "image",
			Components: &[]cdx.Component{{
				Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "second", PackageURL: "pkg:generic/app@1",
			}},
		}

		Expect(rewriteCatalogRefs(published, verified)).To(Succeed())

		var result verifiedCatalog
		property, _ := catalogPropertyOf(published)
		Expect(json.Unmarshal([]byte(property.Value), &result)).To(Succeed())
		Expect(lo.Keys(result.Components)).To(ConsistOf("first"))
		Expect(result.Records[0].Components).To(Equal([]string{"first"}))
		Expect(result.Records[0].Owners).To(Equal([]string{"first"}), "an owner is a ref like any other")
		Expect(result.Records[1].Components).To(Equal([]string{"first"}),
			"two records naming one component name one ref")
	})

	It("says nothing about a document carrying no catalog", func() {
		published := &cdx.BOM{Components: &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "app"}}}

		Expect(rewriteCatalogRefs(published, &cdx.BOM{Components: &[]cdx.Component{proven}})).To(Succeed())
	})
})
