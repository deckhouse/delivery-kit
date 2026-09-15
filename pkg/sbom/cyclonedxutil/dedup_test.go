package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("dedupJSONSlice", func() {
	It("removes identical components", func() {
		items := []cdx.Component{
			{Name: "a", Version: "1.0"},
			{Name: "b", Version: "2.0"},
			{Name: "a", Version: "1.0"},
		}
		result := dedupJSONSlice(items)
		Expect(result).To(HaveLen(2))
		Expect(result[0].Name).To(Equal("a"))
		Expect(result[1].Name).To(Equal("b"))
	})

	It("keeps components that differ by any field", func() {
		items := []cdx.Component{
			{Name: "a", Version: "1.0"},
			{Name: "a", Version: "2.0"},
		}
		result := dedupJSONSlice(items)
		Expect(result).To(HaveLen(2))
	})

	It("returns empty slice unchanged", func() {
		result := dedupJSONSlice([]cdx.Component{})
		Expect(result).To(BeEmpty())
	})

	It("returns nil slice unchanged", func() {
		result := dedupJSONSlice[cdx.Component](nil)
		Expect(result).To(BeNil())
	})

	It("preserves order (first occurrence wins)", func() {
		items := []cdx.Component{
			{Name: "c", Version: "1.0"},
			{Name: "a", Version: "1.0"},
			{Name: "b", Version: "1.0"},
			{Name: "a", Version: "1.0"},
			{Name: "c", Version: "1.0"},
		}
		result := dedupJSONSlice(items)
		Expect(result).To(HaveLen(3))
		Expect(result[0].Name).To(Equal("c"))
		Expect(result[1].Name).To(Equal("a"))
		Expect(result[2].Name).To(Equal("b"))
	})

	It("deduplicates dependencies", func() {
		items := []cdx.Dependency{
			{Ref: "pkg:npm/lodash@4.17.21", Dependencies: &[]string{"dep-a"}},
			{Ref: "pkg:npm/lodash@4.17.21", Dependencies: &[]string{"dep-a"}},
		}
		result := dedupJSONSlice(items)
		Expect(result).To(HaveLen(1))
	})

	It("deduplicates vulnerabilities", func() {
		items := []cdx.Vulnerability{
			{ID: "CVE-2024-0001", Description: "test"},
			{ID: "CVE-2024-0001", Description: "test"},
			{ID: "CVE-2024-0002", Description: "other"},
		}
		result := dedupJSONSlice(items)
		Expect(result).To(HaveLen(2))
	})
})

var _ = Describe("dedupPtrSlice", func() {
	It("returns nil for nil input", func() {
		result := dedupPtrSlice[cdx.Component](nil)
		Expect(result).To(BeNil())
	})

	It("deduplicates and returns pointer", func() {
		items := &[]cdx.Component{
			{Name: "a", Version: "1.0"},
			{Name: "a", Version: "1.0"},
			{Name: "b", Version: "2.0"},
		}
		result := dedupPtrSlice(items)
		Expect(result).ToNot(BeNil())
		Expect(*result).To(HaveLen(2))
	})
})

var _ = Describe("DedupBOM", func() {
	It("deduplicates all uniqueItems sections", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "comp", Version: "1.0"},
				{Name: "comp", Version: "1.0"},
			},
			Services: &[]cdx.Service{
				{Name: "svc"},
				{Name: "svc"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "ref-1"},
				{Ref: "ref-1"},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-1"},
				{ID: "CVE-1"},
			},
			Compositions: &[]cdx.Composition{
				{Aggregate: cdx.CompositionAggregateComplete},
				{Aggregate: cdx.CompositionAggregateComplete},
			},
			Annotations: &[]cdx.Annotation{
				{Text: "note"},
				{Text: "note"},
			},
			Formulation: &[]cdx.Formula{
				{BOMRef: "f1"},
				{BOMRef: "f1"},
			},
		}

		DedupBOM(bom)

		Expect(*bom.Components).To(HaveLen(1))
		Expect(*bom.Services).To(HaveLen(1))
		Expect(*bom.Dependencies).To(HaveLen(1))
		Expect(*bom.Vulnerabilities).To(HaveLen(1))
		Expect(*bom.Compositions).To(HaveLen(1))
		Expect(*bom.Annotations).To(HaveLen(1))
		Expect(*bom.Formulation).To(HaveLen(1))
	})

	It("redirects dependency refs of removed duplicates to the surviving component", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "libc-a", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=aaa"},
				{BOMRef: "libc-b", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=bbb"},
				{BOMRef: "curl", Name: "curl", PackageURL: "pkg:deb/debian/curl@8.12.1"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "curl", Dependencies: &[]string{"libc-b"}},
				{Ref: "libc-b", Dependencies: &[]string{"ld-linux"}},
			},
		}

		DedupBOM(bom)

		Expect(*bom.Components).To(HaveLen(2))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"libc-a"}))
		Expect((*bom.Dependencies)[1].Ref).To(Equal("libc-a"))
		Expect(*(*bom.Dependencies)[1].Dependencies).To(Equal([]string{"ld-linux"}))
	})

	It("merges dependency entries that collapse onto the same surviving ref", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "libc-a", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=aaa"},
				{BOMRef: "libc-b", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=bbb"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "libc-a", Dependencies: &[]string{"ld-linux"}, Provides: &[]string{"libc.so.6"}},
				{Ref: "libc-b", Dependencies: &[]string{"ld-linux", "libgcc"}, Provides: &[]string{"libc.so.6"}},
			},
		}

		DedupBOM(bom)

		Expect(*bom.Dependencies).To(HaveLen(1))
		Expect((*bom.Dependencies)[0].Ref).To(Equal("libc-a"))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"ld-linux", "libgcc"}))
		Expect(*(*bom.Dependencies)[0].Provides).To(Equal([]string{"libc.so.6"}))
	})

	It("redirects provides refs of removed duplicates", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "libc-a", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=aaa"},
				{BOMRef: "libc-b", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=bbb"},
				{BOMRef: "curl", Name: "curl", PackageURL: "pkg:deb/debian/curl@8.12.1"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "curl", Provides: &[]string{"libc-b"}},
			},
		}

		DedupBOM(bom)

		Expect(*(*bom.Dependencies)[0].Provides).To(Equal([]string{"libc-a"}))
	})

	It("drops self-references created by redirection", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "libc-a", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=aaa"},
				{BOMRef: "libc-b", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=bbb"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "libc-a", Dependencies: &[]string{"libc-b"}},
			},
		}

		DedupBOM(bom)

		Expect(*bom.Dependencies).To(HaveLen(1))
		Expect((*bom.Dependencies)[0].Ref).To(Equal("libc-a"))
		Expect((*bom.Dependencies)[0].Dependencies).To(BeNil())
	})

	It("handles nil BOM", func() {
		Expect(func() { DedupBOM(nil) }).ToNot(Panic())
	})

	It("handles BOM with nil sections", func() {
		bom := &cdx.BOM{}
		DedupBOM(bom)
		Expect(bom.Components).To(BeNil())
		Expect(bom.Services).To(BeNil())
	})

	It("deduplicates externalReferences inside components", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "binutils",
					PackageURL: "pkg:apk/wolfi/binutils@2.46-r1",
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://example.com/binutils", Type: cdx.ERTypeVCS},
						{URL: "https://example.com/binutils", Type: cdx.ERTypeVCS},
						{URL: "https://example.com/binutils", Type: cdx.ERTypeVCS},
					},
				},
				{
					Name:       "zlib",
					PackageURL: "pkg:apk/wolfi/zlib@1.3.2-r0",
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://example.com/zlib", Type: cdx.ERTypeVCS},
						{URL: "https://example.com/zlib", Type: cdx.ERTypeDistribution},
						{URL: "https://example.com/zlib", Type: cdx.ERTypeVCS},
					},
				},
			},
		}

		DedupBOM(bom)

		comps := *bom.Components
		Expect(comps).To(HaveLen(2))
		Expect(*comps[0].ExternalReferences).To(HaveLen(1))
		Expect((*comps[0].ExternalReferences)[0].URL).To(Equal("https://example.com/binutils"))
		Expect(*comps[1].ExternalReferences).To(HaveLen(2))
	})

	It("deduplicates BOM-level externalReferences", func() {
		bom := &cdx.BOM{
			ExternalReferences: &[]cdx.ExternalReference{
				{URL: "https://example.com/repo", Type: cdx.ERTypeVCS},
				{URL: "https://example.com/repo", Type: cdx.ERTypeVCS},
				{URL: "https://example.com/docs", Type: cdx.ERTypeDocumentation},
			},
		}

		DedupBOM(bom)

		Expect(*bom.ExternalReferences).To(HaveLen(2))
	})

	It("preserves component with no externalReferences", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "no-refs", PackageURL: "pkg:apk/wolfi/norefs@1.0"},
			},
		}

		DedupBOM(bom)

		Expect(*bom.Components).To(HaveLen(1))
		Expect((*bom.Components)[0].ExternalReferences).To(BeNil())
	})
})
