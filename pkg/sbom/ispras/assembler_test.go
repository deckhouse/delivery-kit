package ispras

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

func imageBOM(imageName string) *cdx.BOM {
	bom := &cdx.BOM{
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

	NamespaceBOMRefs(bom, imageName)

	return bom
}

func gostProperties() *[]cdx.Property {
	return &[]cdx.Property{
		{Name: gost.PropertyAttackSurface, Value: "no"},
		{Name: gost.PropertySecurityFunction, Value: "no"},
	}
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
})
