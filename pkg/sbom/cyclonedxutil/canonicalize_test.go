package cyclonedxutil

import (
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
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

var _ = Describe("Canonicalize", func() {
	It("handles nil BOM", func() {
		Expect(func() { Canonicalize(nil) }).ToNot(Panic())
	})

	It("handles BOM with nil sections", func() {
		bom := &cdx.BOM{}
		Canonicalize(bom)
		Expect(bom.Components).To(BeNil())
		Expect(bom.Services).To(BeNil())
		Expect(bom.Dependencies).To(BeNil())
	})

	It("merges components sharing a purl and ignores the package-id qualifier", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef:     "ref-a",
					Type:       cdx.ComponentTypeLibrary,
					Name:       "zlib",
					Version:    "1.3",
					PackageURL: "pkg:apk/alpine/zlib@1.3?package-id=aaa",
					Properties: &[]cdx.Property{{Name: "syft:package:type", Value: "apk"}},
				},
				{
					BOMRef:             "ref-b",
					Type:               cdx.ComponentTypeLibrary,
					Name:               "zlib",
					Version:            "1.3",
					PackageURL:         "pkg:apk/alpine/zlib@1.3?package-id=bbb",
					ExternalReferences: &[]cdx.ExternalReference{{URL: "https://github.com/madler/zlib", Type: cdx.ERTypeVCS}},
					Properties:         &[]cdx.Property{{Name: "syft:package:foundBy", Value: "apkdb-cataloger"}},
				},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Components).To(HaveLen(1))
		comp := (*bom.Components)[0]
		Expect(comp.BOMRef).To(Equal("ref-a"))
		Expect(*comp.ExternalReferences).To(HaveLen(1))
		Expect(*comp.Properties).To(HaveLen(2))
	})

	It("merges components without a purl by their coordinates", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "os-1", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20"},
				{BOMRef: "os-2", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20"},
				{BOMRef: "os-3", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.21"},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Components).To(HaveLen(2))
		Expect((*bom.Components)[0].BOMRef).To(Equal("os-1"))
		Expect((*bom.Components)[1].BOMRef).To(Equal("os-3"))
	})

	It("unions the licenses and hashes of merged components", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "a", Type: cdx.ComponentTypeLibrary, Name: "bin", Version: "1",
					Hashes:   &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "aaa"}},
					Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
				},
				{
					BOMRef: "b", Type: cdx.ComponentTypeLibrary, Name: "bin", Version: "1",
					Hashes:   &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "aaa"}, {Algorithm: cdx.HashAlgoMD5, Value: "bbb"}},
					Licenses: &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
					CPE:      "cpe:2.3:a:vendor:bin:1:*:*:*:*:*:*:*",
				},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Components).To(HaveLen(1))
		comp := (*bom.Components)[0]
		Expect(*comp.Hashes).To(HaveLen(2))
		Expect(*comp.Licenses).To(HaveLen(2))
		Expect(comp.CPE).To(Equal("cpe:2.3:a:vendor:bin:1:*:*:*:*:*:*:*"))
	})

	It("gives a survivor without a bom-ref the ref of its duplicate so the graph stays attached", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=aaa"},
				{BOMRef: "libc-b", Name: "libc", PackageURL: "pkg:deb/debian/libc@2.36?package-id=bbb"},
				{BOMRef: "curl", Name: "curl", PackageURL: "pkg:deb/debian/curl@8.12.1"},
			},
			Dependencies: &[]cdx.Dependency{{Ref: "curl", Dependencies: &[]string{"libc-b"}}},
		}

		Canonicalize(bom)

		Expect(*bom.Components).To(HaveLen(2))
		Expect((*bom.Components)[0].BOMRef).To(Equal("libc-b"))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"libc-b"}))
	})

	It("merges files by content, never by name alone", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "f1", Type: cdx.ComponentTypeFile, Name: "bin", Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "aaa"}}},
				{BOMRef: "f2", Type: cdx.ComponentTypeFile, Name: "bin", Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "bbb"}}},
				{BOMRef: "f3", Type: cdx.ComponentTypeFile, Name: "bin", Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "aaa"}}},
				{BOMRef: "f4", Type: cdx.ComponentTypeFile, Name: "bin"},
				{BOMRef: "f5", Type: cdx.ComponentTypeFile, Name: "bin"},
			},
			Dependencies: &[]cdx.Dependency{{Ref: "f3", Dependencies: &[]string{"f2"}}},
		}

		Canonicalize(bom)

		refs := lo.Map(*bom.Components, func(c cdx.Component, _ int) string { return c.BOMRef })
		Expect(refs).To(Equal([]string{"f1", "f2", "f4", "f5"}))
		Expect((*bom.Dependencies)[0].Ref).To(Equal("f1"))
	})

	It("keeps only license expressions when a merged duplicate carries one", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "a", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1", PackageURL: "pkg:golang/lib@1",
					Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
				},
				{
					BOMRef: "b", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1", PackageURL: "pkg:golang/lib@1",
					Licenses: &cdx.Licenses{{Expression: "MIT OR Apache-2.0"}},
				},
			},
		}

		Canonicalize(bom)

		Expect(*(*bom.Components)[0].Licenses).To(Equal(cdx.Licenses{{Expression: "MIT OR Apache-2.0"}}))
	})

	It("is idempotent", func() {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeContainer, Name: "img"}},
			Components: &[]cdx.Component{
				{BOMRef: "os-a", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20", Properties: &[]cdx.Property{{Name: gost.PropertyAttackSurface, Value: "no"}}},
				{BOMRef: "os-b", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20", Properties: &[]cdx.Property{{Name: gost.PropertyAttackSurface, Value: "yes"}}},
				{
					BOMRef: "lib-a", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1", PackageURL: "pkg:golang/lib@1?package-id=a",
					ExternalReferences: &[]cdx.ExternalReference{{URL: "https://a", Type: cdx.ERTypeVCS}},
					Components:         &[]cdx.Component{{BOMRef: "n1", Type: cdx.ComponentTypeLibrary, Name: "n", Version: "1"}, {BOMRef: "n2", Type: cdx.ComponentTypeLibrary, Name: "n", Version: "1"}},
				},
				{
					BOMRef: "lib-b", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1", PackageURL: "pkg:golang/lib@1?package-id=b",
					ExternalReferences: &[]cdx.ExternalReference{{URL: "https://b", Type: cdx.ERTypeVCS}, {URL: "https://a", Type: cdx.ERTypeVCS}},
				},
				{BOMRef: "f", Type: cdx.ComponentTypeFile, Name: "bin"},
			},
			Services: &[]cdx.Service{{BOMRef: "s1", Name: "svc"}, {BOMRef: "s2", Name: "svc"}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"os-b", "lib-b", "ghost"}},
				{Ref: "os-a", Dependencies: &[]string{"lib-a", "lib-b", "n2"}},
				{Ref: "os-b", Dependencies: &[]string{"os-a", "s2"}},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "lib-b"}}},
				{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "lib-a"}}, CWEs: &[]int{79}},
			},
			Compositions: &[]cdx.Composition{{Aggregate: cdx.CompositionAggregateComplete, Dependencies: &[]cdx.BOMReference{"lib-b", "os-b"}}},
		}

		Canonicalize(bom)
		once, err := json.Marshal(bom)
		Expect(err).NotTo(HaveOccurred())

		Canonicalize(bom)
		twice, err := json.Marshal(bom)
		Expect(err).NotTo(HaveOccurred())

		Expect(string(twice)).To(Equal(string(once)))
	})

	It("rewrites every ref of a merged duplicate to the surviving component", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "keep", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"},
				{BOMRef: "drop", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"},
				{BOMRef: "root", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"drop"}},
				{Ref: "drop"},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "drop"}}},
			},
			Compositions: &[]cdx.Composition{
				{Aggregate: cdx.CompositionAggregateComplete, Assemblies: &[]cdx.BOMReference{"drop"}},
			},
			Annotations: &[]cdx.Annotation{
				{Text: "note", Subjects: &[]cdx.BOMReference{"drop"}},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Components).To(HaveLen(2))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"keep"}))
		Expect((*(*bom.Vulnerabilities)[0].Affects)[0].Ref).To(Equal("keep"))
		Expect(*(*bom.Compositions)[0].Assemblies).To(Equal([]cdx.BOMReference{"keep"}))
		Expect(*(*bom.Annotations)[0].Subjects).To(Equal([]cdx.BOMReference{"keep"}))
	})

	It("merges dependency entries sharing a ref and keeps dependsOn unique", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "keep", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"},
				{BOMRef: "drop", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"},
				{BOMRef: "root", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"keep", "drop"}},
				{Ref: "root", Dependencies: &[]string{"drop"}, Provides: &[]string{"keep"}},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Dependencies).To(HaveLen(1))
		dep := (*bom.Dependencies)[0]
		Expect(*dep.Dependencies).To(Equal([]string{"keep"}))
		Expect(*dep.Provides).To(Equal([]string{"keep"}))
	})

	It("drops dependency refs that no entity declares", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeOS, Name: "alpine", Version: "3.20"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"gone"}},
				{Ref: "gone"},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Dependencies).To(HaveLen(1))
		Expect((*bom.Dependencies)[0].Ref).To(Equal("root"))
		Expect((*bom.Dependencies)[0].Dependencies).To(BeNil())
	})

	It("keeps a dependency graph of a BOM that declares no entity", func() {
		bom := &cdx.BOM{
			Dependencies: &[]cdx.Dependency{
				{Ref: "ref-1", Dependencies: &[]string{"ref-2"}},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Dependencies).To(HaveLen(1))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"ref-2"}))
	})

	It("merges nested components", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "container", Type: cdx.ComponentTypeContainer, Name: "img",
					Components: &[]cdx.Component{
						{BOMRef: "nested-a", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"},
						{BOMRef: "nested-b", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"},
					},
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "container", Dependencies: &[]string{"nested-a", "nested-b"}},
			},
		}

		Canonicalize(bom)

		nested := *(*bom.Components)[0].Components
		Expect(nested).To(HaveLen(1))
		Expect(nested[0].BOMRef).To(Equal("nested-a"))
		Expect(*(*bom.Dependencies)[0].Dependencies).To(Equal([]string{"nested-a"}))
	})

	It("keeps components with the same purl in different containers apart", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "img-a", Type: cdx.ComponentTypeContainer, Name: "a",
					Components: &[]cdx.Component{{BOMRef: "a/lib", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"}},
				},
				{
					BOMRef: "img-b", Type: cdx.ComponentTypeContainer, Name: "b",
					Components: &[]cdx.Component{{BOMRef: "b/lib", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0"}},
				},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Components).To(HaveLen(2))
		Expect(*(*bom.Components)[0].Components).To(HaveLen(1))
		Expect(*(*bom.Components)[1].Components).To(HaveLen(1))
	})

	It("deduplicates external references and keeps a single vcs reference", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "ref", Type: cdx.ComponentTypeLibrary, Name: "zlib", Version: "1.3", PackageURL: "pkg:apk/alpine/zlib@1.3",
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://github.com/madler/zlib", Type: cdx.ERTypeVCS},
						{URL: "https://github.com/madler/zlib", Type: cdx.ERTypeVCS},
						{URL: "https://git.alpinelinux.org/aports", Type: cdx.ERTypeVCS},
						{URL: "https://example.com/zlib.tar.gz", Type: cdx.ERTypeDistribution},
						{URL: "https://example.com/zlib.tar.gz", Type: cdx.ERTypeDistribution},
					},
				},
			},
			ExternalReferences: &[]cdx.ExternalReference{
				{URL: "https://example.com/docs", Type: cdx.ERTypeDocumentation},
				{URL: "https://example.com/docs", Type: cdx.ERTypeDocumentation},
			},
		}

		Canonicalize(bom)

		refs := *(*bom.Components)[0].ExternalReferences
		Expect(refs).To(HaveLen(2))
		Expect(refs[0].URL).To(Equal("https://github.com/madler/zlib"))
		Expect(refs[1].Type).To(Equal(cdx.ERTypeDistribution))
		Expect(*bom.ExternalReferences).To(HaveLen(1))
	})

	It("deduplicates properties and keeps the strongest value per GOST property", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "ref", Type: cdx.ComponentTypeLibrary, Name: "lib", Version: "1.0", PackageURL: "pkg:golang/lib@1.0",
					Properties: &[]cdx.Property{
						{Name: "syft:package:type", Value: "go-module"},
						{Name: "syft:package:type", Value: "go-module"},
						{Name: gost.PropertyAttackSurface, Value: "no"},
						{Name: gost.PropertyAttackSurface, Value: "yes"},
					},
				},
			},
			Properties: &[]cdx.Property{
				{Name: "werf:image", Value: "app"},
				{Name: "werf:image", Value: "app"},
			},
		}

		Canonicalize(bom)

		props := *(*bom.Components)[0].Properties
		Expect(props).To(HaveLen(2))
		Expect(props[1].Value).To(Equal("yes"))
		Expect(*bom.Properties).To(HaveLen(1))
	})

	It("merges vulnerabilities sharing an id and source", func() {
		bom := &cdx.BOM{
			Vulnerabilities: &[]cdx.Vulnerability{
				{ID: "CVE-1", Source: &cdx.Source{Name: "nvd"}, Affects: &[]cdx.Affects{{Ref: "a"}}, CWEs: &[]int{79}},
				{
					ID: "CVE-1", Source: &cdx.Source{Name: "nvd"}, Affects: &[]cdx.Affects{{Ref: "b"}, {Ref: "a"}},
					CWEs:    &[]int{79, 89},
					Ratings: &[]cdx.VulnerabilityRating{{Score: lo.ToPtr(7.5), Severity: cdx.SeverityHigh}},
				},
				{ID: "CVE-1", Source: &cdx.Source{Name: "ghsa"}},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Vulnerabilities).To(HaveLen(2))
		merged := (*bom.Vulnerabilities)[0]
		Expect(*merged.Affects).To(HaveLen(2))
		Expect(*merged.CWEs).To(Equal([]int{79, 89}))
		Expect(*merged.Ratings).To(HaveLen(1))
	})

	It("merges duplicate services", func() {
		bom := &cdx.BOM{
			Services: &[]cdx.Service{
				{BOMRef: "svc-1", Name: "api", Version: "1.0"},
				{BOMRef: "svc-2", Name: "api", Version: "1.0", ExternalReferences: &[]cdx.ExternalReference{{URL: "https://example.com", Type: cdx.ERTypeWebsite}}},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "svc-1", Dependencies: &[]string{"svc-2"}},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Services).To(HaveLen(1))
		Expect(*(*bom.Services)[0].ExternalReferences).To(HaveLen(1))
		Expect((*bom.Dependencies)[0].Dependencies).To(BeNil())
	})
})
