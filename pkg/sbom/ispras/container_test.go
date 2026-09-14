package ispras

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("ContainerAssembler", func() {
	imageBOM := func(name string, deps map[string][]string, purls ...string) *ImageSBOM {
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

	collectRefs := func(components []cdx.Component) map[string]struct{} {
		refs := map[string]struct{}{}
		var walk func([]cdx.Component)
		walk = func(comps []cdx.Component) {
			for _, c := range comps {
				refs[c.BOMRef] = struct{}{}
				walk(lo.FromPtr(c.Components))
			}
		}
		walk(components)

		return refs
	}

	It("keeps every dependency ref resolvable to a component", func() {
		app := imageBOM("app",
			map[string][]string{
				"pkg:deb/debian/curl@8.12.1": {"pkg:deb/debian/openssl@3.0.15", "pkg:deb/debian/libc6@2.36"},
			},
			"pkg:deb/debian/curl@8.12.1", "pkg:deb/debian/openssl@3.0.15", "pkg:deb/debian/libc6@2.36",
		)
		base := imageBOM("base",
			map[string][]string{
				"pkg:deb/debian/jq@1.6": {"pkg:deb/debian/libc6@2.36"},
			},
			"pkg:deb/debian/jq@1.6", "pkg:deb/debian/libc6@2.36",
		)

		result, err := (&ContainerAssembler{}).Assemble(context.Background(), []*ImageSBOM{app, base}, ProductMeta{AppName: "product"})
		Expect(err).NotTo(HaveOccurred())

		refs := collectRefs(lo.FromPtr(result.Components))

		deps := lo.FromPtr(result.Dependencies)
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
