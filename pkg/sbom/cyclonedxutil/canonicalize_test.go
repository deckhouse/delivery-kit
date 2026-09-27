package cyclonedxutil

import (
	"encoding/json"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
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

	It("takes every field the survivor lacks from the merged duplicate", func() {
		dup := cdx.Component{
			BOMRef: "b", Type: cdx.ComponentTypeLibrary, Name: "bin", Version: "1", PackageURL: "pkg:generic/bin@1",
			MIMEType: "application/octet-stream", Group: "grp", Author: "someone", Publisher: "pub", Copyright: "(c)",
			Description: "desc", Scope: cdx.ScopeRequired, CPE: "cpe:2.3:a:v:bin:1:*:*:*:*:*:*:*",
			Supplier: &cdx.OrganizationalEntity{Name: "supplier"}, Manufacturer: &cdx.OrganizationalEntity{Name: "maker"},
			Authors:   &[]cdx.OrganizationalContact{{Name: "author"}},
			OmniborID: &[]string{"gitoid:blob:sha1:1"}, SWHID: &[]string{"swh:1:cnt:1"}, Tags: &[]string{"t"},
			SWID: &cdx.SWID{TagID: "tag", Name: "bin"}, Modified: lo.ToPtr(true),
			Pedigree: &cdx.Pedigree{Notes: "notes"}, Evidence: &cdx.Evidence{Copyright: &[]cdx.Copyright{{Text: "(c)"}}},
			ReleaseNotes: &cdx.ReleaseNotes{Type: "major"}, ModelCard: &cdx.MLModelCard{BOMRef: "card"},
			Data: &[]cdx.ComponentData{{Name: "data"}}, CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm},
			Signature: &cdx.JSFSignature{Signers: &[]cdx.JSFSigner{{Value: "sig"}}},
		}
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "a", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:generic/bin@1"},
			dup,
		}}

		Canonicalize(bom)

		want := dup
		want.BOMRef = "a"
		Expect(*bom.Components).To(Equal([]cdx.Component{want}))
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

	It("leaves a ref alone when a merged duplicate shared it with a component that survives", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "r", Type: cdx.ComponentTypeLibrary, Name: "a", PackageURL: "pkg:golang/p1@1"},
				{BOMRef: "r2", Type: cdx.ComponentTypeLibrary, Name: "b", PackageURL: "pkg:golang/p1@1"},
				{BOMRef: "r2", Type: cdx.ComponentTypeLibrary, Name: "c", PackageURL: "pkg:golang/p2@1"},
			},
			Dependencies: &[]cdx.Dependency{{Ref: "r", Dependencies: &[]string{"r2"}}},
		}

		Canonicalize(bom)

		Expect(lo.Map(*bom.Components, func(c cdx.Component, _ int) string { return c.Name })).To(Equal([]string{"a", "c"}))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "r", Dependencies: &[]string{"r2"}}}))
	})

	It("canonicalizes the components nested under the metadata component", func() {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{Component: &cdx.Component{
				BOMRef: "root", Type: cdx.ComponentTypeContainer, Name: "img",
				Components: &[]cdx.Component{
					{BOMRef: "nested-a", Type: cdx.ComponentTypeLibrary, Name: "lib", PackageURL: "pkg:golang/lib@1"},
					{BOMRef: "nested-b", Type: cdx.ComponentTypeLibrary, Name: "lib", PackageURL: "pkg:golang/lib@1"},
				},
			}},
			Components:   &[]cdx.Component{{BOMRef: "top", Type: cdx.ComponentTypeLibrary, Name: "top", PackageURL: "pkg:golang/top@1"}},
			Dependencies: &[]cdx.Dependency{{Ref: "top", Dependencies: &[]string{"nested-b"}}},
		}

		Canonicalize(bom)

		Expect(*bom.Metadata.Component.Components).To(HaveLen(1))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "top", Dependencies: &[]string{"nested-a"}}}))
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

	It("redirects a ref through a chain of merges onto the component that survives", func() {
		kid := func(ref string) cdx.Component {
			return cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeLibrary, Name: "kid", Version: "1"}
		}
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "p1", Type: cdx.ComponentTypeLibrary, Name: "parent", Version: "1",
					Components: &[]cdx.Component{kid("child-a")},
				},
				{
					BOMRef: "p2", Type: cdx.ComponentTypeLibrary, Name: "parent", Version: "1",
					Components: &[]cdx.Component{kid("child-b"), kid("child-c")},
				},
			},
			Dependencies:    &[]cdx.Dependency{{Ref: "p1", Dependencies: &[]string{"child-c"}}},
			Vulnerabilities: &[]cdx.Vulnerability{{ID: "CVE-1", Affects: &[]cdx.Affects{{Ref: "child-c"}}}},
		}

		Canonicalize(bom)

		Expect(*(*bom.Components)[0].Components).To(HaveLen(1))
		Expect((*(*bom.Components)[0].Components)[0].BOMRef).To(Equal("child-a"))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "p1", Dependencies: &[]string{"child-a"}}}))
		Expect(*(*bom.Vulnerabilities)[0].Affects).To(Equal([]cdx.Affects{{Ref: "child-a"}}))
	})

	It("prefers the vcs reference reported by the package source over a resolved one", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef: "ref", Type: cdx.ComponentTypeLibrary, Name: "make", Version: "4.4", PackageURL: "pkg:generic/make@4.4",
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://git.savannah.gnu.org/make.git", Type: cdx.ERTypeVCS, Comment: ExternalReferenceCommentResolved},
						{URL: "git://git.savannah.gnu.org/make.git", Type: cdx.ERTypeVCS},
					},
				},
				{
					BOMRef: "ref2", Type: cdx.ComponentTypeLibrary, Name: "bash", Version: "5.3", PackageURL: "pkg:generic/bash@5.3",
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://a.example/bash.git", Type: cdx.ERTypeVCS, Comment: ExternalReferenceCommentResolved},
						{URL: "https://b.example/bash.git", Type: cdx.ERTypeVCS, Comment: ExternalReferenceCommentResolved},
					},
				},
			},
		}

		Canonicalize(bom)

		Expect(*(*bom.Components)[0].ExternalReferences).To(Equal([]cdx.ExternalReference{{URL: "git://git.savannah.gnu.org/make.git", Type: cdx.ERTypeVCS}}))
		Expect(*(*bom.Components)[1].ExternalReferences).To(HaveLen(1))
		Expect((*(*bom.Components)[1].ExternalReferences)[0].URL).To(Equal("https://a.example/bash.git"))
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

	It("keeps every vcs reference of the document and of a service", func() {
		vcs := []cdx.ExternalReference{
			{URL: "https://github.com/madler/zlib", Type: cdx.ERTypeVCS},
			{URL: "https://github.com/openssl/openssl", Type: cdx.ERTypeVCS},
			{URL: "https://github.com/openssl/openssl", Type: cdx.ERTypeVCS},
		}
		bom := &cdx.BOM{
			ExternalReferences: lo.ToPtr(slices.Clone(vcs)),
			Services:           &[]cdx.Service{{BOMRef: "svc", Name: "api", ExternalReferences: lo.ToPtr(slices.Clone(vcs))}},
		}

		Canonicalize(bom)

		Expect(*bom.ExternalReferences).To(Equal(vcs[:2]))
		Expect(*(*bom.Services)[0].ExternalReferences).To(Equal(vcs[:2]))
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

	It("takes every field of a merged vulnerability that the survivor lacks", func() {
		dup := cdx.Vulnerability{
			BOMRef: "v2", ID: "CVE-1", Source: &cdx.Source{Name: "nvd"},
			Description: "desc", Detail: "detail", Recommendation: "upgrade", Workaround: "none",
			Created: "2024-01-01", Published: "2024-01-02", Updated: "2024-01-03", Rejected: "2024-01-04",
			ProofOfConcept: &cdx.ProofOfConcept{Environment: "poc"},
			Credits:        &cdx.Credits{Individuals: &[]cdx.OrganizationalContact{{Name: "finder"}}},
			Tools:          &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "scanner"}}},
			Analysis:       &cdx.VulnerabilityAnalysis{State: cdx.IASNotAffected},
			Affects:        &[]cdx.Affects{{Ref: "a"}},
		}
		bom := &cdx.BOM{
			Components: &[]cdx.Component{{BOMRef: "a", Type: cdx.ComponentTypeLibrary, Name: "a", Version: "1"}},
			Vulnerabilities: &[]cdx.Vulnerability{
				{BOMRef: "v1", ID: "CVE-1", Source: &cdx.Source{Name: "nvd"}, Affects: &[]cdx.Affects{{Ref: "a"}}},
				dup,
			},
		}

		Canonicalize(bom)

		want := dup
		want.BOMRef = "v1"
		Expect(*bom.Vulnerabilities).To(Equal([]cdx.Vulnerability{want}))
	})

	It("rewrites the refs pointing at a merged vulnerability to the survivor", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{{BOMRef: "a", Type: cdx.ComponentTypeLibrary, Name: "a", Version: "1"}},
			Vulnerabilities: &[]cdx.Vulnerability{
				{BOMRef: "v1", ID: "CVE-1", Source: &cdx.Source{Name: "nvd"}},
				{BOMRef: "v2", ID: "CVE-1", Source: &cdx.Source{Name: "nvd"}},
			},
			Compositions: &[]cdx.Composition{{Aggregate: cdx.CompositionAggregateComplete, Vulnerabilities: &[]cdx.BOMReference{"v1", "v2"}}},
			Annotations:  &[]cdx.Annotation{{BOMRef: "an", Subjects: &[]cdx.BOMReference{"v2"}, Text: "x"}},
		}

		Canonicalize(bom)

		Expect(*bom.Vulnerabilities).To(HaveLen(1))
		Expect(*(*bom.Compositions)[0].Vulnerabilities).To(Equal([]cdx.BOMReference{"v1"}))
		Expect(*(*bom.Annotations)[0].Subjects).To(Equal([]cdx.BOMReference{"v1"}))
	})

	It("keeps a dependency on an entity of another document", func() {
		bom := &cdx.BOM{
			Components:   &[]cdx.Component{{BOMRef: "c1", Type: cdx.ComponentTypeLibrary, Name: "c", Version: "1"}},
			Dependencies: &[]cdx.Dependency{{Ref: "c1", Dependencies: &[]string{"urn:cdx:11111111-1111-1111-1111-111111111111/1#lib", "gone"}}},
		}

		Canonicalize(bom)

		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "c1", Dependencies: &[]string{"urn:cdx:11111111-1111-1111-1111-111111111111/1#lib"}}}))
	})

	It("drops the composition and annotation refs that point at nothing", func() {
		bom := &cdx.BOM{
			SerialNumber:    "urn:uuid:22222222-2222-2222-2222-222222222222",
			Components:      &[]cdx.Component{{BOMRef: "c1", Type: cdx.ComponentTypeLibrary, Name: "c", Version: "1"}},
			Vulnerabilities: &[]cdx.Vulnerability{{BOMRef: "v1", ID: "CVE-1"}},
			Compositions: &[]cdx.Composition{
				{Aggregate: cdx.CompositionAggregateComplete, Assemblies: &[]cdx.BOMReference{"c1", "gone"}, Dependencies: &[]cdx.BOMReference{"gone"}, Vulnerabilities: &[]cdx.BOMReference{"v1", "gone"}},
				{Aggregate: cdx.CompositionAggregateIncomplete, Assemblies: &[]cdx.BOMReference{"gone"}},
				{Aggregate: cdx.CompositionAggregateUnknown},
			},
			Annotations: &[]cdx.Annotation{
				{BOMRef: "a1", Subjects: &[]cdx.BOMReference{"c1", "gone"}, Text: "x"},
				{BOMRef: "a2", Subjects: &[]cdx.BOMReference{"gone"}, Text: "y"},
				{BOMRef: "a3", Subjects: &[]cdx.BOMReference{"urn:cdx:11111111-1111-1111-1111-111111111111/1#other"}, Text: "z"},
				{BOMRef: "a4", Subjects: &[]cdx.BOMReference{"urn:uuid:22222222-2222-2222-2222-222222222222"}, Text: "about the bom"},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Compositions).To(Equal([]cdx.Composition{
			{Aggregate: cdx.CompositionAggregateComplete, Assemblies: &[]cdx.BOMReference{"c1"}, Vulnerabilities: &[]cdx.BOMReference{"v1"}},
			{Aggregate: cdx.CompositionAggregateUnknown},
		}))
		Expect(*bom.Annotations).To(Equal([]cdx.Annotation{
			{BOMRef: "a1", Subjects: &[]cdx.BOMReference{"c1"}, Text: "x"},
			{BOMRef: "a3", Subjects: &[]cdx.BOMReference{"urn:cdx:11111111-1111-1111-1111-111111111111/1#other"}, Text: "z"},
			{BOMRef: "a4", Subjects: &[]cdx.BOMReference{"urn:uuid:22222222-2222-2222-2222-222222222222"}, Text: "about the bom"},
		}))
	})

	It("keeps an annotation about a formula or a composition the document declares", func() {
		bom := &cdx.BOM{
			Components:  &[]cdx.Component{{BOMRef: "c1", Type: cdx.ComponentTypeLibrary, Name: "c", Version: "1"}},
			Formulation: &[]cdx.Formula{{BOMRef: "formula"}},
			Compositions: &[]cdx.Composition{
				{BOMRef: "composition", Aggregate: cdx.CompositionAggregateComplete, Assemblies: &[]cdx.BOMReference{"c1"}},
			},
			Annotations: &[]cdx.Annotation{
				{BOMRef: "a1", Subjects: &[]cdx.BOMReference{"formula"}, Text: "about the formula"},
				{BOMRef: "a2", Subjects: &[]cdx.BOMReference{"composition"}, Text: "about the composition"},
				{BOMRef: "a3", Subjects: &[]cdx.BOMReference{"dropped"}, Text: "about a dropped composition"},
			},
		}

		Canonicalize(bom)

		Expect(*bom.Annotations).To(Equal([]cdx.Annotation{
			{BOMRef: "a1", Subjects: &[]cdx.BOMReference{"formula"}, Text: "about the formula"},
			{BOMRef: "a2", Subjects: &[]cdx.BOMReference{"composition"}, Text: "about the composition"},
		}))
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

	It("folds a duplicate service into the survivor, nested services included", func() {
		bom := &cdx.BOM{
			Services: &[]cdx.Service{
				{BOMRef: "svc-1", Name: "api", Version: "1.0", Endpoints: &[]string{"https://a.example"}, Tags: &[]string{"a"}},
				{
					BOMRef: "svc-2", Name: "api", Version: "1.0", Description: "the api", TrustZone: "dmz",
					Authenticated: lo.ToPtr(true), Endpoints: &[]string{"https://b.example"}, Tags: &[]string{"a", "b"},
					Provider: &cdx.OrganizationalEntity{Name: "acme"},
					Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
					Services: &[]cdx.Service{{BOMRef: "inner", Name: "sub", Version: "1"}},
				},
			},
			Components:   &[]cdx.Component{{BOMRef: "c", Type: cdx.ComponentTypeLibrary, Name: "c", PackageURL: "pkg:golang/c@1"}},
			Dependencies: &[]cdx.Dependency{{Ref: "c", Dependencies: &[]string{"inner", "svc-2"}}},
		}

		Canonicalize(bom)

		Expect(*bom.Services).To(Equal([]cdx.Service{{
			BOMRef: "svc-1", Name: "api", Version: "1.0", Description: "the api", TrustZone: "dmz",
			Authenticated: lo.ToPtr(true), Endpoints: &[]string{"https://a.example", "https://b.example"}, Tags: &[]string{"a", "b"},
			Provider: &cdx.OrganizationalEntity{Name: "acme"},
			Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
			Services: &[]cdx.Service{{BOMRef: "inner", Name: "sub", Version: "1"}},
		}}))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "c", Dependencies: &[]string{"inner", "svc-1"}}}))
	})

	It("redirects a ref to the nested service of a merged duplicate onto the surviving nested service", func() {
		bom := &cdx.BOM{
			Services: &[]cdx.Service{
				{BOMRef: "svc-1", Name: "api", Services: &[]cdx.Service{{BOMRef: "inner-1", Name: "sub"}}},
				{BOMRef: "svc-2", Name: "api", Services: &[]cdx.Service{{BOMRef: "inner-2", Name: "sub"}}},
			},
			Components:   &[]cdx.Component{{BOMRef: "c", Type: cdx.ComponentTypeLibrary, Name: "c", PackageURL: "pkg:golang/c@1"}},
			Dependencies: &[]cdx.Dependency{{Ref: "c", Dependencies: &[]string{"inner-2"}}},
		}

		Canonicalize(bom)

		Expect(*(*bom.Services)[0].Services).To(Equal([]cdx.Service{{BOMRef: "inner-1", Name: "sub"}}))
		Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "c", Dependencies: &[]string{"inner-1"}}}))
	})
})
