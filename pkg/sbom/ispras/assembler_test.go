package ispras

import (
	"context"
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

func imageBOM(imageName string) *cdx.BOM {
	bom := rawImageBOM(imageName)
	NamespaceBOMRefs(bom, imageName)

	return bom
}

func rawImageBOM(imageName string) *cdx.BOM {
	return &cdx.BOM{
		BOMFormat:   cdx.BOMFormat,
		SpecVersion: cdx.SpecVersion1_6,
		Version:     1,
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeContainer, Name: "registry.example.com/" + imageName, Version: "v1"},
		},
		Components: &[]cdx.Component{
			{
				BOMRef: "os", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20",
				Properties: gostProperties(),
			},
			{
				BOMRef: "lib", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0",
				Properties: gostProperties(),
			},
		},
		Dependencies: &[]cdx.Dependency{
			{Ref: "root", Dependencies: &[]string{"os"}},
			{Ref: "os", Dependencies: &[]string{"lib"}, Provides: &[]string{"lib"}},
		},
		Vulnerabilities: &[]cdx.Vulnerability{{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "lib"}}}},
	}
}

func gostProperties() *[]cdx.Property {
	return &[]cdx.Property{
		{Name: gost.PropertyAttackSurface, Value: "no"},
		{Name: gost.PropertySecurityFunction, Value: "no"},
	}
}

func dependsOn(bom *cdx.BOM, ref string) []string {
	var result []string
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		if dep.Ref == ref {
			result = append(result, lo.FromPtr(dep.Dependencies)...)
		}
	}

	return result
}

func collectRefs(components []cdx.Component) map[string]struct{} {
	refs := make(map[string]struct{})
	for _, comp := range components {
		if comp.BOMRef != "" {
			refs[comp.BOMRef] = struct{}{}
		}
		if comp.Components != nil {
			for ref := range collectRefs(*comp.Components) {
				refs[ref] = struct{}{}
			}
		}
	}

	return refs
}

var _ = Describe("ContainerAssembler", func() {
	It("keeps every dependency ref pointing at a component of the result", func() {
		images := []*ImageSBOM{
			NewImageSBOM("a", imageBOM("a")),
			NewImageSBOM("b", imageBOM("b")),
		}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), images, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		refs := collectRefs(*result.Components)
		Expect(*result.Dependencies).To(HaveLen(4))
		for _, dep := range *result.Dependencies {
			Expect(refs).To(HaveKey(dep.Ref))
			for _, ref := range *dep.Dependencies {
				Expect(refs).To(HaveKey(ref))
			}
		}
		Expect((*result.Dependencies)[0]).To(Equal(cdx.Dependency{Ref: "a", Dependencies: &[]string{"a/os"}}))
	})

	It("keeps the same package in every container it belongs to", func() {
		images := []*ImageSBOM{
			NewImageSBOM("a", imageBOM("a")),
			NewImageSBOM("b", imageBOM("b")),
		}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), images, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		containers := *result.Components
		Expect(containers).To(HaveLen(2))
		for _, container := range containers {
			Expect(*container.Components).To(HaveLen(2))
		}
	})

	It("keeps one declaration of a service two images share", func() {
		bomA, bomB := rawImageBOM("a"), rawImageBOM("b")
		bomA.Services = &[]cdx.Service{{BOMRef: "svc", Name: "api"}}
		bomB.Services = &[]cdx.Service{{BOMRef: "svc", Name: "api"}}
		*bomA.Dependencies = append(*bomA.Dependencies, cdx.Dependency{Ref: "os", Dependencies: &[]string{"svc"}})
		*bomB.Dependencies = append(*bomB.Dependencies, cdx.Dependency{Ref: "lib", Dependencies: &[]string{"svc"}})
		NamespaceBOMRefs(bomA, "a")
		NamespaceBOMRefs(bomB, "b")

		images := []*ImageSBOM{NewImageSBOM("a", bomA), NewImageSBOM("b", bomB)}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), images, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		Expect(*result.Services).To(HaveLen(1))
		survivor := (*result.Services)[0]
		Expect(survivor.Name).To(Equal("api"))
		Expect(*result.Components).To(HaveLen(2))
		Expect(dependsOn(result, "a/os")).To(ContainElement(survivor.BOMRef))
		Expect(dependsOn(result, "b/lib")).To(ContainElement(survivor.BOMRef))
	})

	It("keeps a component nested under the image root and the edges to it", func() {
		bom := rawImageBOM("a")
		bom.Metadata.Component.Components = &[]cdx.Component{
			{BOMRef: "nested", Type: cdx.ComponentTypeLibrary, Name: "nested", Version: "1"},
		}
		*bom.Dependencies = append(*bom.Dependencies, cdx.Dependency{Ref: "lib", Dependencies: &[]string{"nested"}})
		NamespaceBOMRefs(bom, "a")

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bom)}, ProductMeta{AppName: "app", AppVersion: "1"})
		Expect(err).NotTo(HaveOccurred())

		Expect(collectRefs(*result.Components)).To(HaveKey("a/nested"))
		Expect(dependsOn(result, "a/lib")).To(ContainElement("a/nested"))
	})

	It("keeps two services of different identity apart when the images reuse one ref for them", func() {
		bomA, bomB := rawImageBOM("a"), rawImageBOM("b")
		bomA.Services = &[]cdx.Service{{BOMRef: "svc", Name: "api"}}
		bomB.Services = &[]cdx.Service{{BOMRef: "svc", Name: "db"}}
		*bomA.Dependencies = append(*bomA.Dependencies, cdx.Dependency{Ref: "os", Dependencies: &[]string{"svc"}})
		*bomB.Dependencies = append(*bomB.Dependencies, cdx.Dependency{Ref: "os", Dependencies: &[]string{"svc"}})
		NamespaceBOMRefs(bomA, "a")
		NamespaceBOMRefs(bomB, "b")

		images := []*ImageSBOM{NewImageSBOM("a", bomA), NewImageSBOM("b", bomB)}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), images, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		services := *result.Services
		Expect(services).To(HaveLen(2))
		Expect(services[0].BOMRef).NotTo(Equal(services[1].BOMRef))

		refByName := map[string]string{}
		for _, svc := range services {
			refByName[svc.Name] = svc.BOMRef
		}
		Expect(dependsOn(result, "a/os")).To(ContainElement(refByName["api"]))
		Expect(dependsOn(result, "b/os")).To(ContainElement(refByName["db"]))
	})

	It("keeps the properties of the image root on the container, its GOST values ahead of the aggregate", func() {
		bom := imageBOM("a")
		bom.Metadata.Component.Properties = &[]cdx.Property{
			{Name: "root-only", Value: "r"},
			{Name: gost.PropertyAttackSurface, Value: "no"},
			{Name: gost.PropertySecurityFunction, Value: "no"},
		}
		(*bom.Components)[1].Properties = &[]cdx.Property{{Name: gost.PropertyAttackSurface, Value: "yes"}, {Name: gost.PropertySecurityFunction, Value: "yes"}}
		bom.Properties = &[]cdx.Property{{Name: "doc", Value: "d"}}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bom)}, ProductMeta{})
		Expect(err).NotTo(HaveOccurred())

		container := (*result.Components)[0]
		Expect(*container.Properties).To(ContainElements(cdx.Property{Name: "root-only", Value: "r"}, cdx.Property{Name: "doc", Value: "d"}))
		Expect(gost.GetComponent(&container)).To(Equal(gost.Config{AttackSurface: gost.GostValueNo, SecurityFunction: gost.GostValueNo}))
	})

	It("keeps the annotations about a formula and a composition of an image", func() {
		bom := rawImageBOM("a")
		bom.Formulation = &[]cdx.Formula{{BOMRef: "formula"}}
		bom.Compositions = &[]cdx.Composition{{BOMRef: "composition", Aggregate: cdx.CompositionAggregateComplete, Assemblies: &[]cdx.BOMReference{"lib"}}}
		bom.Annotations = &[]cdx.Annotation{
			{BOMRef: "a1", Subjects: &[]cdx.BOMReference{"formula"}, Text: "about the formula"},
			{BOMRef: "a2", Subjects: &[]cdx.BOMReference{"composition"}, Text: "about the composition"},
		}
		NamespaceBOMRefs(bom, "a")

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bom)}, ProductMeta{})
		Expect(err).NotTo(HaveOccurred())

		Expect(lo.Map(lo.FromPtr(result.Annotations), func(a cdx.Annotation, _ int) string { return a.Text })).
			To(ConsistOf("about the formula", "about the composition"))
		Expect(*(*result.Annotations)[0].Subjects).To(Equal([]cdx.BOMReference{"a/formula"}))
		Expect(*(*result.Annotations)[1].Subjects).To(Equal([]cdx.BOMReference{"a/composition"}))
	})

	It("keeps an annotation about the document of an image as a link to that document", func() {
		bom := rawImageBOM("a")
		bom.SerialNumber = "urn:uuid:11111111-1111-1111-1111-111111111111"
		bom.Annotations = &[]cdx.Annotation{{BOMRef: "a1", Subjects: &[]cdx.BOMReference{cdx.BOMReference(bom.SerialNumber)}, Text: "about the document"}}
		NamespaceBOMRefs(bom, "a")

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bom)}, ProductMeta{})
		Expect(err).NotTo(HaveOccurred())

		Expect(lo.FromPtr(result.Annotations)).To(HaveLen(1))
		Expect((*result.Annotations)[0].Text).To(Equal("about the document"))
		Expect(*(*result.Annotations)[0].Subjects).To(Equal([]cdx.BOMReference{"urn:cdx:11111111-1111-1111-1111-111111111111/1"}))
	})

	It("aggregates the GOST values of the components nested under the image root too", func() {
		bom := rawImageBOM("a")
		nested := cdx.Component{BOMRef: "nested", Type: cdx.ComponentTypeLibrary, Name: "nested", Version: "1.0"}
		gost.SetComponent(&nested, gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes})
		bom.Metadata.Component.Components = &[]cdx.Component{nested}
		NamespaceBOMRefs(bom, "a")

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bom)}, ProductMeta{})
		Expect(err).NotTo(HaveOccurred())

		container := (*result.Components)[0]
		Expect(gost.GetComponent(&container)).To(Equal(gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes}))
	})

	It("moves the document properties of every image onto its container", func() {
		bomA, bomB := imageBOM("a"), imageBOM("b")
		bomA.Properties = &[]cdx.Property{{Name: "custom", Value: "x"}}
		bomB.Properties = &[]cdx.Property{{Name: "custom", Value: "y"}}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bomA), NewImageSBOM("b", bomB)}, ProductMeta{})
		Expect(err).NotTo(HaveOccurred())

		Expect(result.Properties).To(BeNil())
		Expect(*(*result.Components)[0].Properties).To(ContainElement(cdx.Property{Name: "custom", Value: "x"}))
		Expect(*(*result.Components)[0].Properties).To(HaveLen(3))
		Expect(*(*result.Components)[1].Properties).To(ContainElement(cdx.Property{Name: "custom", Value: "y"}))
	})

	It("gives the container the external references of the image root only", func() {
		bomA, bomB := imageBOM("a"), imageBOM("b")
		bomA.Metadata.Component.ExternalReferences = &[]cdx.ExternalReference{{URL: "https://git.example.com/image-a", Type: cdx.ERTypeVCS}}
		bomA.ExternalReferences = &[]cdx.ExternalReference{
			{URL: "https://github.com/madler/zlib", Type: cdx.ERTypeVCS},
			{URL: "https://github.com/openssl/openssl", Type: cdx.ERTypeVCS},
		}
		bomB.ExternalReferences = &[]cdx.ExternalReference{{URL: "https://github.com/openssl/openssl", Type: cdx.ERTypeVCS}}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bomA), NewImageSBOM("b", bomB)}, ProductMeta{})
		Expect(err).NotTo(HaveOccurred())

		Expect(*(*result.Components)[0].ExternalReferences).To(Equal([]cdx.ExternalReference{{URL: "https://git.example.com/image-a", Type: cdx.ERTypeVCS}}))
		Expect((*result.Components)[1].ExternalReferences).To(BeNil())
		Expect(*result.ExternalReferences).To(Equal([]cdx.ExternalReference{
			{URL: "https://github.com/madler/zlib", Type: cdx.ERTypeVCS},
			{URL: "https://github.com/openssl/openssl", Type: cdx.ERTypeVCS},
		}))
	})

	It("keeps images apart when their metadata purls are equal", func() {
		bomA, bomB := imageBOM("a"), imageBOM("b")
		bomA.Metadata.Component.PackageURL = "pkg:oci/shared@sha256:aaa"
		bomB.Metadata.Component.PackageURL = "pkg:oci/shared@sha256:aaa"

		images := []*ImageSBOM{NewImageSBOM("a", bomA), NewImageSBOM("b", bomB)}

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), images, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		containers := *result.Components
		Expect(containers).To(HaveLen(2))
		Expect(lo.Map(containers, func(c cdx.Component, _ int) string { return c.BOMRef })).To(ConsistOf("a", "b"))
		for _, container := range containers {
			Expect(*container.Components).To(HaveLen(2))
		}
	})

	It("redirects every reference to the image root, not only dependency subjects", func() {
		bom := imageBOM("a")
		bom.Vulnerabilities = &[]cdx.Vulnerability{{ID: "CVE-2", Affects: &[]cdx.Affects{{Ref: "a/root"}}}}
		bom.Dependencies = &[]cdx.Dependency{{Ref: "a/os", Dependencies: &[]string{"a/root"}}}
		before, err := json.Marshal(bom)
		Expect(err).NotTo(HaveOccurred())

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{NewImageSBOM("a", bom)}, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		Expect(*(*result.Vulnerabilities)[0].Affects).To(Equal([]cdx.Affects{{Ref: "a"}}))
		Expect(*result.Dependencies).To(Equal([]cdx.Dependency{{Ref: "a/os", Dependencies: &[]string{"a"}}}))

		after, err := json.Marshal(bom)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(after)).To(Equal(string(before)))
	})

	It("keeps the graphs of images sharing a package apart", func() {
		imageWithGraph := func(name string, deps map[string][]string, purls ...string) *ImageSBOM {
			components := lo.Map(purls, func(purl string, _ int) cdx.Component {
				return cdx.Component{BOMRef: purl, Type: cdx.ComponentTypeLibrary, Name: purl, PackageURL: purl}
			})
			dependencies := lo.MapToSlice(deps, func(ref string, dependsOn []string) cdx.Dependency {
				return cdx.Dependency{Ref: ref, Dependencies: lo.ToPtr(dependsOn)}
			})
			bom := &cdx.BOM{
				BOMFormat:    cdx.BOMFormat,
				SpecVersion:  cdx.SpecVersion1_6,
				Metadata:     &cdx.Metadata{Component: &cdx.Component{BOMRef: name, Type: cdx.ComponentTypeContainer, Name: name}},
				Components:   &components,
				Dependencies: &dependencies,
			}
			NamespaceBOMRefs(bom, name)

			return NewImageSBOM(name, bom)
		}

		app := imageWithGraph("app",
			map[string][]string{"pkg:deb/debian/curl@8.12.1": {"pkg:deb/debian/openssl@3.0.15", "pkg:deb/debian/libc6@2.36"}},
			"pkg:deb/debian/curl@8.12.1", "pkg:deb/debian/openssl@3.0.15", "pkg:deb/debian/libc6@2.36",
		)
		base := imageWithGraph("base",
			map[string][]string{"pkg:deb/debian/jq@1.6": {"pkg:deb/debian/libc6@2.36"}},
			"pkg:deb/debian/jq@1.6", "pkg:deb/debian/libc6@2.36",
		)

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{app, base}, ProductMeta{AppName: "product"})
		Expect(err).NotTo(HaveOccurred())

		refs := collectRefs(*result.Components)
		deps := *result.Dependencies
		Expect(deps).To(HaveLen(2))
		for _, dep := range deps {
			Expect(refs).To(HaveKey(dep.Ref), "dependency subject %q has no component", dep.Ref)
			for _, target := range lo.FromPtr(dep.Dependencies) {
				Expect(refs).To(HaveKey(target), "dependency target %q of %q has no component", target, dep.Ref)
			}
		}
		Expect(lo.Map(deps, func(d cdx.Dependency, _ int) string { return d.Ref })).To(ConsistOf(
			"app/pkg:deb/debian/curl@8.12.1",
			"base/pkg:deb/debian/jq@1.6",
		))
	})
})

var _ = Describe("OSSAssembler", func() {
	It("merges identical packages of different images into one component", func() {
		images := []*ImageSBOM{
			NewImageSBOM("a", imageBOM("a")),
			NewImageSBOM("b", imageBOM("b")),
		}

		result, err := (&OSSAssembler{}).Assemble(context.Background(), images, ProductMeta{AppName: "app", AppVersion: "1", Manufacturer: "m"})
		Expect(err).NotTo(HaveOccurred())

		Expect(*result.Components).To(HaveLen(2))

		refs := collectRefs(*result.Components)
		for _, dep := range *result.Dependencies {
			Expect(refs).To(HaveKey(dep.Ref))
			for _, ref := range *dep.Dependencies {
				Expect(refs).To(HaveKey(ref))
			}
		}
	})
})

var _ = Describe("NamespaceBOMRefs", func() {
	It("namespaces every declared ref and every reference to it", func() {
		bom := imageBOM("img")

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
