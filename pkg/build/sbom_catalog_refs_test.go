package build

import (
	"encoding/json"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
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
			Metadata:   &cdx.Metadata{Properties: &[]cdx.Property{{Name: nativegate.CatalogProperty, Value: catalog}}},
			Components: lo.ToPtr(components),
		}
		verified := &cdx.BOM{Components: &[]cdx.Component{proven}}

		return published, verified
	}

	// The three steps a convergence takes, run here in one go, so these can ask what a
	// whole convergence does not produce.
	rewrite := func(published, verified *cdx.BOM) error {
		GinkgoHelper()
		refs, err := trackCatalogRefs(published, verified)
		if err != nil {
			return err
		}
		if err := refs.observe(published); err != nil {
			return err
		}

		return refs.rewrite(published)
	}

	It("refuses a catalog naming a component the verification never declared", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[{"path":"/app","sha256":"sha256:00","origin":"build",` +
			`"components":["urn:dk:component:sha256:ffff"]}],"components":{}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})

		err := rewrite(published, verified)

		Expect(err).To(MatchError(ContainSubstring("/app: the verification did not prove urn:dk:component:sha256:ffff")))
	})

	It("refuses to publish when a component the verification proved is gone from the document", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[],"components":{}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "other", Version: "9", BOMRef: "derived", PackageURL: "pkg:generic/other@9",
		})

		err := rewrite(published, verified)

		Expect(err).To(MatchError(ContainSubstring(
			"invalid: the published document holds no component the verification proved: urn:dk:component:sha256:aaaa")))
	})

	// A document may hold one component in more than one place - among its own
	// components and again under the image it describes. The translation must settle on
	// one of them, and on the same one every time, or two records naming one component
	// would point at two different refs.
	It("settles on the ref the document declares first", func() {
		const (
			one = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
			two = "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
		)
		catalog := `{"schema":"dk.catalog/v5","records":[` +
			`{"path":"/app","sha256":"` + one + `","origin":"pm",` +
			`"components":["urn:dk:component:sha256:aaaa"],"owners":["urn:dk:component:sha256:aaaa"]},` +
			`{"path":"/app2","sha256":"` + two + `","origin":"pm",` +
			`"components":["urn:dk:component:sha256:aaaa"],"owners":["urn:dk:component:sha256:aaaa"]}],` +
			`"components":{"urn:dk:component:sha256:aaaa":` +
			`{"type":"library","name":"app","version":"1","purl":"pkg:generic/app@1","bom-ref":"urn:dk:component:sha256:aaaa"}}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "first", PackageURL: "pkg:generic/app@1",
		})
		published.Metadata.Component = &cdx.Component{
			Type: cdx.ComponentTypeContainer, Name: "image", BOMRef: "image",
			Components: &[]cdx.Component{{
				Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "second", PackageURL: "pkg:generic/app@1",
			}},
		}

		Expect(rewrite(published, verified)).To(Succeed())

		var result nativegate.Catalog
		property, _ := catalogPropertyOf(published)
		Expect(json.Unmarshal([]byte(property.Value), &result)).To(Succeed())
		Expect(lo.Keys(result.Components)).To(ConsistOf("first"))
		Expect(result.Components["first"].BOMRef).To(Equal("first"),
			"a catalog holds each component under its own ref, and a reader checks the two agree")
		Expect(result.Records[0].Components).To(Equal([]string{"first"}))
		Expect(result.Records[0].Owners).To(Equal([]string{"first"}), "an owner is a ref like any other")
		Expect(result.Records[1].Components).To(Equal([]string{"first"}),
			"two records naming one component name one ref")
	})

	// A fold is what the canonicalisation does when it finds two components to be one:
	// it keeps the first and remaps the other onto it. The catalog has to name the
	// survivor, which is the component the fold established they both are.
	It("follows a fold to the component that survived it", func(ctx SpecContext) {
		catalog := `{"schema":"dk.catalog/v5","records":[` +
			`{"path":"/app","sha256":"sha256:` + strings.Repeat("3", 64) + `","origin":"pm",` +
			`"components":["urn:dk:component:sha256:aaaa"],"owners":["urn:dk:component:sha256:aaaa"]}],` +
			`"components":{"urn:dk:component:sha256:aaaa":` +
			`{"type":"library","name":"app","version":"1","purl":"pkg:generic/app@1","bom-ref":"urn:dk:component:sha256:aaaa"}}}`
		// The scanned copy stands first, so the fold keeps it and the catalog has to
		// follow it there rather than to the ref the verification was given.
		published, verified := documentWith(catalog,
			cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "scanned", PackageURL: "pkg:generic/app@1?package-id=1"},
			cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "proven", PackageURL: "pkg:generic/app@1?package-id=2"},
		)
		refs, err := trackCatalogRefs(published, verified)
		Expect(err).NotTo(HaveOccurred())
		Expect(refs.observe(published)).To(Succeed())

		cyclonedxutil.Canonicalize(logging.WithLogger(ctx), published)

		Expect(lo.FromPtr(published.Components)).To(HaveLen(1), "the two were found to be one")
		survivor := (*published.Components)[0].BOMRef
		Expect(refs.rewrite(published)).To(Succeed())
		var result nativegate.Catalog
		property, _ := catalogPropertyOf(published)
		Expect(json.Unmarshal([]byte(property.Value), &result)).To(Succeed())
		Expect(lo.Keys(result.Components)).To(ConsistOf(survivor))
		Expect(result.Records[0].Components).To(Equal([]string{survivor}))
	})

	// Between what the patchers left and what is published there is one more pass, and
	// a component it did not keep is a record that resolves to nothing.
	It("refuses to publish when a proven component is gone from the last document", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[` +
			`{"path":"/app","sha256":"sha256:` + strings.Repeat("4", 64) + `","origin":"pm",` +
			`"components":["urn:dk:component:sha256:aaaa"],"owners":["urn:dk:component:sha256:aaaa"]}],` +
			`"components":{"urn:dk:component:sha256:aaaa":` +
			`{"type":"library","name":"app","version":"1","purl":"pkg:generic/app@1","bom-ref":"urn:dk:component:sha256:aaaa"}}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})
		refs, err := trackCatalogRefs(published, verified)
		Expect(err).NotTo(HaveOccurred())
		Expect(refs.observe(published)).To(Succeed())
		published.Components = &[]cdx.Component{}

		Expect(refs.rewrite(published)).To(MatchError(ContainSubstring(
			"the published document holds no component for urn:dk:component:sha256:aaaa")))
	})

	// The catalog is read back the way a consumer reads it, which catches what the refs
	// alone do not: a record this build cannot stand behind is not published either.
	It("refuses to publish a catalog that does not load", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[` +
			`{"path":"/app","sha256":"sha256:` + strings.Repeat("5", 64) + `","origin":"pm",` +
			`"components":["urn:dk:component:sha256:aaaa"]}],` +
			`"components":{"urn:dk:component:sha256:aaaa":` +
			`{"type":"library","name":"app","version":"1","purl":"pkg:generic/app@1","bom-ref":"urn:dk:component:sha256:aaaa"}}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})

		Expect(rewrite(published, verified)).To(MatchError(ContainSubstring(
			"the rewritten catalog does not load: /app: no-data: missing package owners")))
	})

	// Two components the catalog tells apart that the document declares as one would
	// leave one record naming a component describing the other.
	It("refuses two proven components the document declares as one", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[` +
			`{"path":"/app","sha256":"sha256:` + strings.Repeat("6", 64) + `","origin":"pm",` +
			`"components":["urn:dk:component:sha256:aaaa"],"owners":["urn:dk:component:sha256:aaaa"]}],` +
			`"components":{` +
			`"urn:dk:component:sha256:aaaa":{"type":"library","name":"app","version":"1","purl":"pkg:generic/app@1","bom-ref":"urn:dk:component:sha256:aaaa"},` +
			`"urn:dk:component:sha256:bbbb":{"type":"library","name":"app","version":"1","purl":"pkg:generic/app@1","bom-ref":"urn:dk:component:sha256:bbbb"}}}`
		published, _ := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})
		verified := &cdx.BOM{Components: &[]cdx.Component{
			{Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "urn:dk:component:sha256:aaaa", PackageURL: "pkg:generic/app@1"},
			{Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "urn:dk:component:sha256:bbbb", PackageURL: "pkg:generic/app@1"},
		}}

		Expect(rewrite(published, verified)).To(MatchError(ContainSubstring(
			"invalid: the published document declares urn:dk:component:sha256:aaaa and urn:dk:component:sha256:bbbb as one component derived")))
	})

	It("refuses a catalog carrying a field this does not understand", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[],"components":{},"invented":1}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})

		Expect(rewrite(published, verified)).To(MatchError(ContainSubstring("read the verified catalog")))
	})

	It("says nothing about a document carrying no catalog", func() {
		published := &cdx.BOM{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		}}}

		Expect(rewrite(published, &cdx.BOM{Components: &[]cdx.Component{proven}})).To(Succeed())
		_, carries := catalogPropertyOf(published)
		Expect(carries).To(BeFalse())
	})

	// A component the verification proved that no longer stands in the document is a
	// record that resolves to nothing, whether it was dropped before the renaming or
	// after it.
	It("refuses to publish when a proven component is dropped after the patchers", func() {
		catalog := `{"schema":"dk.catalog/v5","records":[],"components":{}}`
		published, verified := documentWith(catalog, cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "derived", PackageURL: "pkg:generic/app@1",
		})

		refs, err := trackCatalogRefs(published, verified)
		Expect(err).NotTo(HaveOccurred())
		published.Components = &[]cdx.Component{}

		Expect(refs.observe(published)).To(MatchError(ContainSubstring(
			"invalid: the document lost components the verification proved: derived")))
	})
})
