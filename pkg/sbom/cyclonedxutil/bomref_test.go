package cyclonedxutil

import (
	"strings"

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

var _ = Describe("deriveBomRef", func() {
	It("appends package-id qualifier to valid PURL", func() {
		ref := deriveBomRef("pkg:deb/debian/curl@7.74.0", "urn:uuid:test-serial", 0)
		Expect(ref).To(HavePrefix("pkg:deb/debian/curl@7.74.0"))
		Expect(ref).To(ContainSubstring("package-id="))
	})

	It("preserves existing PURL qualifiers", func() {
		ref := deriveBomRef("pkg:deb/debian/curl@7.74.0?arch=amd64", "urn:uuid:test-serial", 0)
		Expect(ref).To(ContainSubstring("arch=amd64"))
		Expect(ref).To(ContainSubstring("package-id="))
	})

	It("returns raw ID for empty PURL", func() {
		ref := deriveBomRef("", "urn:uuid:test-serial", 0)
		Expect(ref).ToNot(BeEmpty())
		Expect(strings.HasPrefix(ref, "pkg:")).To(BeFalse())
	})

	It("returns raw ID for invalid PURL", func() {
		ref := deriveBomRef("not-a-purl", "urn:uuid:test-serial", 0)
		Expect(ref).ToNot(BeEmpty())
		Expect(strings.HasPrefix(ref, "pkg:")).To(BeFalse())
	})

	It("generates different refs for different indices", func() {
		ref0 := deriveBomRef("pkg:deb/curl@8.12", "urn:uuid:serial", 0)
		ref1 := deriveBomRef("pkg:deb/curl@8.12", "urn:uuid:serial", 1)
		Expect(ref0).ToNot(Equal(ref1))
	})

	It("generates different refs for different serials", func() {
		ref0 := deriveBomRef("pkg:deb/curl@8.12", "urn:uuid:serial-a", 0)
		ref1 := deriveBomRef("pkg:deb/curl@8.12", "urn:uuid:serial-b", 0)
		Expect(ref0).ToNot(Equal(ref1))
	})
})

var _ = Describe("ensureUniqueBOMRefs", func() {
	It("handles nil BOM without panic", func() {
		Expect(func() { ensureUniqueBOMRefs(nil) }).ToNot(Panic())
	})

	It("skips components with empty bom-ref", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "", Name: "no-ref-comp", Version: "1.0"},
			},
		}
		ensureUniqueBOMRefs(bom)
		Expect((*bom.Components)[0].BOMRef).To(Equal(""))
	})

	It("assigns unique bom-refs to components with PURL", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@7.74", Name: "curl", Version: "7.74"},
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
		}
		ensureUniqueBOMRefs(bom)
		refs := collectBOMRefs(bom)
		Expect(refs).To(HaveLen(2))
		Expect(uniqueStrings(refs)).To(BeTrue())
		Expect(refs[0]).To(ContainSubstring("package-id="))
		Expect(refs[1]).To(ContainSubstring("package-id="))
	})

	It("assigns unique bom-refs to components without PURL", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "comp", Name: "alpha", Version: "1.0"},
				{BOMRef: "comp", Name: "beta", Version: "1.0"},
			},
		}
		ensureUniqueBOMRefs(bom)
		refs := collectBOMRefs(bom)
		Expect(refs).To(HaveLen(2))
		Expect(uniqueStrings(refs)).To(BeTrue())
	})

	It("keeps all components (no dedup by identity)", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "A-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
				{BOMRef: "B-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
		}
		ensureUniqueBOMRefs(bom)
		Expect(*bom.Components).To(HaveLen(2))
		refs := collectBOMRefs(bom)
		Expect(uniqueStrings(refs)).To(BeTrue())
	})

	It("rewrites dependency refs to new bom-refs", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "old-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
				{BOMRef: "old-zlib", PackageURL: "pkg:deb/zlib@1.2", Name: "zlib", Version: "1.2"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "old-curl", Dependencies: &[]string{"old-zlib"}},
			},
		}
		ensureUniqueBOMRefs(bom)

		newCurlRef := (*bom.Components)[0].BOMRef
		newZlibRef := (*bom.Components)[1].BOMRef
		dep := (*bom.Dependencies)[0]
		Expect(dep.Ref).To(Equal(newCurlRef))
		Expect((*dep.Dependencies)[0]).To(Equal(newZlibRef))
	})

	It("rewrites vulnerability affects refs", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "old-curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{BOMRef: "CVE-1", ID: "CVE-2024-0001", Affects: &[]cdx.Affects{{Ref: "old-curl"}}},
			},
		}
		ensureUniqueBOMRefs(bom)

		newCurlRef := (*bom.Components)[0].BOMRef
		Expect(newCurlRef).ToNot(Equal("old-curl"))
		Expect((*(*bom.Vulnerabilities)[0].Affects)[0].Ref).To(Equal(newCurlRef))
	})

	It("assigns unique refs to services", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Services: &[]cdx.Service{
				{BOMRef: "svc", Name: "svc-a", Version: "1.0"},
				{BOMRef: "svc", Name: "svc-b", Version: "2.0"},
			},
		}
		ensureUniqueBOMRefs(bom)
		refs := collectBOMRefs(bom)
		Expect(refs).To(HaveLen(2))
		Expect(uniqueStrings(refs)).To(BeTrue())
	})

	It("is idempotent", func() {
		bom := &cdx.BOM{
			SerialNumber: "urn:uuid:test",
			Components: &[]cdx.Component{
				{BOMRef: "curl", PackageURL: "pkg:deb/curl@8.12", Name: "curl", Version: "8.12"},
			},
		}
		ensureUniqueBOMRefs(bom)
		refsFirst := collectBOMRefs(bom)
		ensureUniqueBOMRefs(bom)
		refsSecond := collectBOMRefs(bom)
		Expect(refsFirst).To(Equal(refsSecond))
	})
})
