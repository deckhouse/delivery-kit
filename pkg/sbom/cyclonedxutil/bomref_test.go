package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func collectBOMRefs(bom *cdx.BOM) []string {
	var refs []string

	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.BOMRef != "" {
				refs = append(refs, c.BOMRef)
			}
		}
	}

	if bom.Services != nil {
		for _, s := range *bom.Services {
			if s.BOMRef != "" {
				refs = append(refs, s.BOMRef)
			}
		}
	}

	if bom.Vulnerabilities != nil {
		for _, v := range *bom.Vulnerabilities {
			if v.BOMRef != "" {
				refs = append(refs, v.BOMRef)
			}
		}
	}

	return refs
}

func uniqueStrings(ss []string) bool {
	seen := map[string]struct{}{}
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			return false
		}
		seen[s] = struct{}{}
	}

	return true
}

var _ = Describe("normalizeBOMRefs", func() {
	It("handles nil BOM without panic", func() {
		Expect(func() { normalizeBOMRefs(nil) }).ToNot(Panic())
	})

	It("passes through components with empty bom-ref unchanged", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "", Name: "no-ref-comp", Version: "1.0"},
			},
		}
		normalizeBOMRefs(bom)
		Expect(bom.Components).ToNot(BeNil())
		Expect((*bom.Components)[0].BOMRef).To(Equal(""))
	})

	It("is idempotent", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "A-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
				{BOMRef: "B-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "B-curl", Dependencies: &[]string{"dep-x"}},
			},
		}
		normalizeBOMRefs(bom)
		refsFirst := collectBOMRefs(bom)
		normalizeBOMRefs(bom)
		refsSecond := collectBOMRefs(bom)
		Expect(refsFirst).To(Equal(refsSecond))
	})

	DescribeTable("identity dedup: components with same PURL are collapsed to first occurrence",
		func(components []cdx.Component, expectedCount int, survivingBOMRef string) {
			bom := &cdx.BOM{
				Components: &components,
			}
			normalizeBOMRefs(bom)
			Expect(bom.Components).ToNot(BeNil())
			Expect(*bom.Components).To(HaveLen(expectedCount))
			if survivingBOMRef != "" {
				Expect((*bom.Components)[0].BOMRef).To(Equal(survivingBOMRef))
			}
			Expect(uniqueStrings(collectBOMRefs(bom))).To(BeTrue())
		},
		Entry("two components, same PURL, different BOMRef — collapsed to 1",
			[]cdx.Component{
				{BOMRef: "A-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
				{BOMRef: "B-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
			1, "A-curl",
		),
		Entry("two components, different PURL, same BOMRef — both survive with unique refs",
			[]cdx.Component{
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@7.74", Name: "curl", Version: "7.74"},
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
			2, "",
		),
		Entry("two components, no PURL, same BOMRef, different name — both survive with unique refs",
			[]cdx.Component{
				{BOMRef: "comp", Name: "alpha", Version: "1.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "comp", Name: "beta", Version: "1.0", Type: cdx.ComponentTypeLibrary},
			},
			2, "",
		),
	)

	It("sets PURL as new BOMRef when resolving component collision", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@7.74", Name: "curl", Version: "7.74"},
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
		}
		normalizeBOMRefs(bom)
		Expect(*bom.Components).To(HaveLen(2))
		var found bool
		for _, c := range *bom.Components {
			if c.PackageURL == "pkg:deb/curl@8.12" {
				Expect(c.BOMRef).To(Equal("pkg:deb/curl@8.12"))
				found = true
			}
		}
		Expect(found).To(BeTrue())
	})

	DescribeTable("cross-reference rewriting after identity dedup",
		func(bom *cdx.BOM, checkRef func(bom *cdx.BOM) string, checkDepCount func(bom *cdx.BOM) int) {
			normalizeBOMRefs(bom)
			Expect(checkRef(bom)).To(Equal("A-curl"))
			if depCount := checkDepCount(bom); depCount >= 0 {
				Expect(depCount).To(Equal(2))
			}
			Expect(uniqueStrings(collectBOMRefs(bom))).To(BeTrue())
		},
		Entry("Dependency.Ref remapped to survivor",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{BOMRef: "A-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
					{BOMRef: "B-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
				},
				Dependencies: &[]cdx.Dependency{
					{Ref: "A-curl", Dependencies: &[]string{"dep-x"}},
					{Ref: "B-curl", Dependencies: &[]string{"dep-y"}},
				},
			},
			func(bom *cdx.BOM) string {
				if bom.Dependencies != nil && len(*bom.Dependencies) > 1 {
					return (*bom.Dependencies)[1].Ref
				}
				return ""
			},
			func(bom *cdx.BOM) int {
				if bom.Dependencies != nil {
					return len(*bom.Dependencies)
				}
				return -1
			},
		),
		Entry("Vulnerability.Affects[].Ref remapped to survivor",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{BOMRef: "A-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
					{BOMRef: "B-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{BOMRef: "CVE-1", ID: "CVE-2024-0001", Affects: &[]cdx.Affects{{Ref: "B-curl"}}},
				},
			},
			func(bom *cdx.BOM) string {
				if bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) > 0 {
					v := (*bom.Vulnerabilities)[0]
					if v.Affects != nil && len(*v.Affects) > 0 {
						return (*v.Affects)[0].Ref
					}
				}
				return ""
			},
			func(bom *cdx.BOM) int { return -1 },
		),
	)

	DescribeTable("collision resolution for non-component entity types",
		func(bom *cdx.BOM, expectedCount int) {
			normalizeBOMRefs(bom)
			Expect(uniqueStrings(collectBOMRefs(bom))).To(BeTrue())
			refs := collectBOMRefs(bom)
			Expect(refs).To(HaveLen(expectedCount))
		},
		Entry("two services with same BOMRef, different names",
			&cdx.BOM{
				Services: &[]cdx.Service{
					{BOMRef: "svc", Name: "svc-a", Version: "1.0"},
					{BOMRef: "svc", Name: "svc-b", Version: "2.0"},
				},
			},
			2,
		),
		Entry("two vulnerabilities with same BOMRef, different IDs",
			&cdx.BOM{
				Vulnerabilities: &[]cdx.Vulnerability{
					{BOMRef: "vuln-1", ID: "CVE-2024-0001"},
					{BOMRef: "vuln-1", ID: "CVE-2024-0002"},
				},
			},
			2,
		),
	)
})
