package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("NamespaceBOMRefs", func() {
	It("namespaces every declared ref and every reference to it", func() {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			Metadata:    &cdx.Metadata{Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeContainer, Name: "img"}},
			Components: &[]cdx.Component{
				{BOMRef: "os", Type: cdx.ComponentTypeOS, Name: "alpine"},
				{BOMRef: "lib", Type: cdx.ComponentTypeLibrary, Name: "lib"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"os"}},
				{Ref: "os", Dependencies: &[]string{"lib"}, Provides: &[]string{"lib"}},
			},
			Vulnerabilities: &[]cdx.Vulnerability{{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "lib"}}}},
		}
		NamespaceBOMRefs(bom, "img")

		Expect(bom.Metadata.Component.BOMRef).To(Equal("img/root"))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{
			{Ref: "img/root", Dependencies: &[]string{"img/os"}},
			{Ref: "img/os", Dependencies: &[]string{"img/lib"}, Provides: &[]string{"img/lib"}},
		}))
		Expect((*(*bom.Vulnerabilities)[0].Affects)[0].Ref).To(Equal("img/lib"))
	})

	It("namespaces service declarations and the references to them, nested services included", func() {
		bom := &cdx.BOM{
			Components:   &[]cdx.Component{{BOMRef: "os", Type: cdx.ComponentTypeOS, Name: "alpine"}},
			Services:     &[]cdx.Service{{BOMRef: "svc", Name: "api", Services: &[]cdx.Service{{BOMRef: "inner", Name: "sub"}}}},
			Dependencies: &[]cdx.Dependency{{Ref: "os", Dependencies: &[]string{"svc", "inner"}}, {Ref: "svc", Dependencies: &[]string{"os"}}},
		}

		NamespaceBOMRefs(bom, "img")

		Expect((*bom.Services)[0].BOMRef).To(Equal("img/svc"))
		Expect((*(*bom.Services)[0].Services)[0].BOMRef).To(Equal("img/inner"))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{
			{Ref: "img/os", Dependencies: &[]string{"img/svc", "img/inner"}},
			{Ref: "img/svc", Dependencies: &[]string{"img/os"}},
		}))
	})

	It("namespaces the refs declared by tools, formulation and vulnerabilities", func() {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{Tools: &cdx.ToolsChoice{
				Components: &[]cdx.Component{{BOMRef: "syft", Type: cdx.ComponentTypeApplication, Name: "syft"}},
				Services:   &[]cdx.Service{{BOMRef: "scan", Name: "scan"}},
			}},
			Components: &[]cdx.Component{{BOMRef: "os", Type: cdx.ComponentTypeOS, Name: "alpine"}},
			Formulation: &[]cdx.Formula{{
				BOMRef:     "formula",
				Components: &[]cdx.Component{{BOMRef: "build-input", Type: cdx.ComponentTypeLibrary, Name: "in"}},
				Services:   &[]cdx.Service{{BOMRef: "build-svc", Name: "ci"}},
			}},
			Vulnerabilities: &[]cdx.Vulnerability{{BOMRef: "vuln", ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "os"}}}},
			Compositions:    &[]cdx.Composition{{Aggregate: cdx.CompositionAggregateComplete, Vulnerabilities: &[]cdx.BOMReference{"vuln"}}},
			Annotations:     &[]cdx.Annotation{{BOMRef: "note", Subjects: &[]cdx.BOMReference{"syft", "formula"}, Text: "x"}},
		}

		NamespaceBOMRefs(bom, "img")

		Expect((*bom.Metadata.Tools.Components)[0].BOMRef).To(Equal("img/syft"))
		Expect((*bom.Metadata.Tools.Services)[0].BOMRef).To(Equal("img/scan"))
		Expect((*bom.Formulation)[0].BOMRef).To(Equal("img/formula"))
		Expect((*(*bom.Formulation)[0].Components)[0].BOMRef).To(Equal("img/build-input"))
		Expect((*(*bom.Formulation)[0].Services)[0].BOMRef).To(Equal("img/build-svc"))
		Expect((*bom.Vulnerabilities)[0].BOMRef).To(Equal("img/vuln"))
		Expect(*(*bom.Compositions)[0].Vulnerabilities).To(Equal([]cdx.BOMReference{"img/vuln"}))
		Expect(*(*bom.Annotations)[0].Subjects).To(Equal([]cdx.BOMReference{"img/syft", "img/formula"}))
	})

	It("namespaces the refs of compositions and annotations and leaves BOM-Links alone", func() {
		bom := &cdx.BOM{
			Components:   &[]cdx.Component{{BOMRef: "os", Type: cdx.ComponentTypeOS, Name: "alpine"}},
			Dependencies: &[]cdx.Dependency{{Ref: "os", Dependencies: &[]string{"urn:cdx:11111111-1111-1111-1111-111111111111/1#lib"}}},
			Compositions: &[]cdx.Composition{{BOMRef: "comp", Aggregate: cdx.CompositionAggregateComplete, Assemblies: &[]cdx.BOMReference{"os"}}},
			Annotations:  &[]cdx.Annotation{{BOMRef: "note", Subjects: &[]cdx.BOMReference{"os", "urn:cdx:11111111-1111-1111-1111-111111111111/1#lib"}, Text: "x"}},
		}

		NamespaceBOMRefs(bom, "img")

		Expect((*bom.Compositions)[0].BOMRef).To(Equal("img/comp"))
		Expect((*bom.Annotations)[0].BOMRef).To(Equal("img/note"))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"urn:cdx:11111111-1111-1111-1111-111111111111/1#lib"}))
		Expect(*(*bom.Annotations)[0].Subjects).To(Equal([]cdx.BOMReference{"img/os", "urn:cdx:11111111-1111-1111-1111-111111111111/1#lib"}))
	})

	It("renames every ref at once when one new ref equals another old one", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "lib", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1"},
				{BOMRef: "img/lib", Type: cdx.ComponentTypeLibrary, Name: "other", Version: "2"},
			},
			Vulnerabilities: &[]cdx.Vulnerability{{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "lib"}}}},
		}

		NamespaceBOMRefs(bom, "img")

		Expect(lo.Map(*bom.Components, func(c cdx.Component, _ int) string { return c.BOMRef })).
			To(Equal([]string{"img/lib", "img/img/lib"}))
		Expect((*(*bom.Vulnerabilities)[0].Affects)[0].Ref).To(Equal("img/lib"))
	})
})
