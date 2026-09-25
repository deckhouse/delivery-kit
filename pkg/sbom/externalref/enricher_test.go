package externalref

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/logging"
)

var _ = Describe("Enricher", func() {
	var ts *httptest.Server
	var enricher *Enricher
	var ctx context.Context

	BeforeEach(func() {
		handler, _ := mockResolver()
		ts = httptest.NewServer(handler)
		service := NewService(ServiceConfig{ServerURL: ts.URL})
		enricher = NewEnricher(service.Resolve)
		ctx = logging.WithLogger(context.Background())
	})

	AfterEach(func() {
		ts.Close()
	})

	Describe("Enrich", func() {
		type enrichCase struct {
			bom   *cdx.BOM
			check func(error)
		}

		DescribeTable("enriches BOM correctly",
			func(c enrichCase) {
				err := enricher.Enrich(ctx, c.bom)
				c.check(err)
			},
			Entry("all components with purl", enrichCase{
				bom: &cdx.BOM{
					Components: &[]cdx.Component{
						{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
						{Name: "express", Version: "4.18.2", PackageURL: "pkg:npm/express@4.18.2", Type: cdx.ComponentTypeLibrary},
					},
				},
				check: func(err error) {
					Expect(err).NotTo(HaveOccurred())
				},
			}),
			Entry("appends to existing external refs", enrichCase{
				bom: &cdx.BOM{
					Components: &[]cdx.Component{
						{
							Name:               "lodash",
							Version:            "4.17.21",
							PackageURL:         "pkg:npm/lodash@4.17.21",
							Type:               cdx.ComponentTypeLibrary,
							ExternalReferences: &[]cdx.ExternalReference{{URL: "https://example.com", Type: cdx.ERTypeWebsite}},
						},
					},
				},
				check: func(err error) {
					Expect(err).NotTo(HaveOccurred())
				},
			}),
			Entry("skips OS component without purl", enrichCase{
				bom: &cdx.BOM{
					Components: &[]cdx.Component{
						{Name: "alpine", Version: "3.21", Type: cdx.ComponentTypeOS},
						{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
					},
				},
				check: func(err error) {
					Expect(err).NotTo(HaveOccurred())
				},
			}),
			Entry("returns aggregated error with component details on library without purl", enrichCase{
				bom: &cdx.BOM{
					Components: &[]cdx.Component{
						{Name: "no-purl-lib", Version: "1.0.0", Type: cdx.ComponentTypeLibrary},
					},
				},
				check: func(err error) {
					Expect(err).To(HaveOccurred())
					errMsg := err.Error()
					Expect(errMsg).To(ContainSubstring("components failed:"))
					Expect(errMsg).To(ContainSubstring("    - component: no-purl-lib: component \"no-purl-lib\" (type \"library\") has no purl\n"))
				},
			}),
			Entry("keeps enriching after a failed resolve", enrichCase{
				bom: &cdx.BOM{
					Components: &[]cdx.Component{
						{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
						{Name: "unknown", Version: "0.0.0", PackageURL: "pkg:npm/unknown@0.0.0", Type: cdx.ComponentTypeLibrary},
					},
				},
				check: func(err error) {
					Expect(err).To(HaveOccurred())
					errMsg := err.Error()
					Expect(errMsg).To(ContainSubstring("components failed:"))
					Expect(errMsg).To(ContainSubstring("unknown"))
				},
			}),
			Entry("collects every failed component instead of stopping at the first", enrichCase{
				bom: &cdx.BOM{
					Components: &[]cdx.Component{
						{Name: "unknown", Version: "0.0.0", PackageURL: "pkg:npm/unknown@0.0.0", Type: cdx.ComponentTypeLibrary},
						{Name: "missing", Version: "0.0.0", PackageURL: "pkg:npm/missing@0.0.0", Type: cdx.ComponentTypeLibrary},
					},
				},
				check: func(err error) {
					Expect(err).To(HaveOccurred())
					errMsg := err.Error()
					Expect(errMsg).To(ContainSubstring("components failed:"))
					Expect(errMsg).To(ContainSubstring("unknown"))
					Expect(errMsg).To(ContainSubstring("missing"))
				},
			}),
			Entry("returns no error on nil components", enrichCase{
				bom: &cdx.BOM{},
				check: func(err error) {
					Expect(err).NotTo(HaveOccurred())
				},
			}),
			Entry("returns no error on empty components", enrichCase{
				bom: &cdx.BOM{Components: &[]cdx.Component{}},
				check: func(err error) {
					Expect(err).NotTo(HaveOccurred())
				},
			}),
		)

		It("sets ExternalReferences on component and BOM level", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			Expect((*bom.Components)[0].ExternalReferences).NotTo(BeNil())

			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(HaveLen(1))
			Expect(refs[0].URL).To(Equal("https://github.com/lodash/lodash"))
			Expect(refs[0].Type).To(Equal(cdx.ERTypeVCS))

			Expect(bom.ExternalReferences).NotTo(BeNil())
			Expect(*bom.ExternalReferences).To(HaveLen(1))
			Expect((*bom.ExternalReferences)[0].URL).To(Equal("https://github.com/lodash/lodash"))
		})

		It("deduplicates BOM-level external references", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash-a", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
					{Name: "lodash-b", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
					{Name: "express", Version: "4.18.2", PackageURL: "pkg:npm/express@4.18.2", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			Expect(*bom.ExternalReferences).To(HaveLen(2))
		})

		It("resolves a duplicated package URL once and enriches every duplicate", func() {
			var calls int32
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				atomic.AddInt32(&calls, 1)
				return &ResolveResult{URL: "https://example.com/" + purl, Kind: "vcs"}, nil
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "dup", Version: "1.0", PackageURL: "pkg:npm/dup@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "dup", Version: "1.0", PackageURL: "pkg:npm/dup@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "dup", Version: "1.0", PackageURL: "pkg:npm/dup@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "other", Version: "2.0", PackageURL: "pkg:npm/other@2.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			Expect(atomic.LoadInt32(&calls)).To(Equal(int32(2)))
			for i := 0; i < 3; i++ {
				Expect((*bom.Components)[i].ExternalReferences).NotTo(BeNil())
				Expect(*(*bom.Components)[i].ExternalReferences).To(HaveLen(1))
			}
		})

		It("reports a duplicated failing package URL once", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return nil, fmt.Errorf("resolve failed")
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "dup", Version: "1.0", PackageURL: "pkg:npm/dup@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "dup", Version: "1.0", PackageURL: "pkg:npm/dup@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "dup", Version: "1.0", PackageURL: "pkg:npm/dup@1.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).To(HaveOccurred())
			Expect(strings.Count(err.Error(), "pkg:npm/dup@1.0")).To(Equal(1))
		})

		It("collapses resolver-unavailable failures into a single summary line", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return nil, ErrResolverUnavailable
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "pkg-b", Version: "2.0", PackageURL: "pkg:npm/pkg-b@2.0", Type: cdx.ComponentTypeLibrary},
					{Name: "pkg-c", Version: "3.0", PackageURL: "pkg:npm/pkg-c@3.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("    - PURL resolver unavailable: resolution skipped for 3 package URLs\n"))
			Expect(err.Error()).NotTo(ContainSubstring("- component: pkg-a"))
			Expect(errors.Is(err, ErrResolverUnavailable)).To(BeTrue(), "terminality detection must survive the grouping")
		})

		It("keeps per-component lines for content failures next to the unavailable summary", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				if purl == "pkg:npm/pkg-a@1.0" {
					return nil, fmt.Errorf("resolve: unexpected status 404")
				}
				return nil, ErrResolverUnavailable
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "pkg-b", Version: "2.0", PackageURL: "pkg:npm/pkg-b@2.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("- component: pkg-a (pkg:npm/pkg-a@1.0): resolve: unexpected status 404"))
			Expect(err.Error()).To(ContainSubstring("resolution skipped for 1 package URLs"))
		})

		It("preserves existing ExternalReferences on component", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{
						Name:               "lodash",
						Version:            "4.17.21",
						PackageURL:         "pkg:npm/lodash@4.17.21",
						Type:               cdx.ComponentTypeLibrary,
						ExternalReferences: &[]cdx.ExternalReference{{URL: "https://example.com", Type: cdx.ERTypeWebsite}},
					},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())

			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(HaveLen(2))
			Expect(refs[0].URL).To(Equal("https://example.com"))
			Expect(refs[1].URL).To(Equal("https://github.com/lodash/lodash"))
		})

		It("keeps a single reference of a type the component already has", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{
						Name:               "lodash",
						Version:            "4.17.21",
						PackageURL:         "pkg:npm/lodash@4.17.21",
						Type:               cdx.ComponentTypeLibrary,
						ExternalReferences: &[]cdx.ExternalReference{{URL: "git://example.com/lodash.git", Type: cdx.ERTypeVCS}},
					},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())

			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(HaveLen(1))
			Expect(refs[0].URL).To(Equal("git://example.com/lodash.git"))
		})

		It("does not duplicate references when an enriched BOM is enriched again", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())

			Expect(*(*bom.Components)[0].ExternalReferences).To(HaveLen(1))
			Expect(*bom.ExternalReferences).To(HaveLen(1))
		})

		It("error string contains component details format: '- <name> (<purl>): <error>'", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return nil, fmt.Errorf("resolve failed")
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
					{Name: "pkg-b", Version: "2.0", PackageURL: "pkg:npm/pkg-b@2.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).To(HaveOccurred())
			errMsg := err.Error()
			Expect(errMsg).To(ContainSubstring("components failed:"))
			Expect(errMsg).To(ContainSubstring("- component: pkg-a (pkg:npm/pkg-a@1.0): resolve failed"))
			Expect(errMsg).To(ContainSubstring("- component: pkg-b (pkg:npm/pkg-b@2.0): resolve failed"))
		})

		It("reports purl for errors produced by the enricher itself", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{URL: "https://example.com", Kind: "unknown"}, nil
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "commons-io", Version: "2.11.0", PackageURL: "pkg:maven/commons-io/commons-io@2.11.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`    - component: commons-io (pkg:maven/commons-io/commons-io@2.11.0): enrich: external reference kind "unknown" is not allowed, expected "vcs" or "source-distribution"` + "\n"))
		})

		It("rejects a kind the SBOM validation does not accept", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{URL: "https://example.com/" + purl, Kind: "website"}, nil
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`external reference kind "website" is not allowed`))
		})

		It("accepts a source-distribution kind", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{
					URL:    "https://example.com/pkg.tgz",
					Kind:   "source-distribution",
					Hashes: []Hash{{Algorithm: "STREEBOG-256", Content: streebog256Content}},
				}, nil
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(HaveLen(1))
			Expect(refs[0].Type).To(Equal(cdx.ERTypeSourceDistribution))
		})

		It("carries the source distribution hashes into the reference", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{
					URL:  "https://example.com/pkg.tgz",
					Kind: "source-distribution",
					Hashes: []Hash{
						{Algorithm: "STREEBOG-256", Content: streebog256Content},
						{Algorithm: "STREEBOG-512", Content: streebog512Content},
					},
				}, nil
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(HaveLen(1))
			Expect(refs[0].Hashes).NotTo(BeNil())
			Expect(*refs[0].Hashes).To(Equal([]cdx.Hash{
				{Algorithm: cdx.HashAlgorithm("STREEBOG-256"), Value: streebog256Content},
				{Algorithm: cdx.HashAlgorithm("STREEBOG-512"), Value: streebog512Content},
			}))
			Expect(*bom.ExternalReferences).To(HaveLen(1))
			Expect(*(*bom.ExternalReferences)[0].Hashes).To(HaveLen(2))
		})

		DescribeTable("replaces a source distribution an earlier enrichment left without a digest",
			func(inheritedHashes *[]cdx.Hash) {
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					return &ResolveResult{
						URL:    "https://example.com/pkg.tgz",
						Kind:   "source-distribution",
						Hashes: []Hash{{Algorithm: "STREEBOG-256", Content: streebog256Content}},
					}, nil
				})

				bom := &cdx.BOM{
					Components: &[]cdx.Component{
						{
							Name:       "pkg-a",
							Version:    "1.0",
							PackageURL: "pkg:npm/pkg-a@1.0",
							Type:       cdx.ComponentTypeLibrary,
							ExternalReferences: &[]cdx.ExternalReference{
								{URL: "https://example.com/old.tgz", Type: cdx.ERTypeSourceDistribution, Hashes: inheritedHashes},
							},
						},
					},
				}

				Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
				refs := *(*bom.Components)[0].ExternalReferences
				Expect(refs).To(HaveLen(1))
				Expect(refs[0].URL).To(Equal("https://example.com/pkg.tgz"))
				Expect(*refs[0].Hashes).To(HaveLen(1))
				Expect(*bom.ExternalReferences).To(HaveLen(1))
				Expect((*bom.ExternalReferences)[0].URL).To(Equal("https://example.com/pkg.tgz"))
			},
			Entry("hashes absent", nil),
			Entry("hashes empty", &[]cdx.Hash{}),
		)

		DescribeTable("keeps a shared source distribution in the BOM list when another component's copy is replaced",
			func(digestFirst bool) {
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					return &ResolveResult{
						URL:    "https://example.com/new.tgz",
						Kind:   "source-distribution",
						Hashes: []Hash{{Algorithm: "STREEBOG-256", Content: streebog256Content}},
					}, nil
				})

				withDigest := cdx.ExternalReference{
					URL:    "https://example.com/old.tgz",
					Type:   cdx.ERTypeSourceDistribution,
					Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgorithm("STREEBOG-512"), Value: streebog512Content}},
				}
				digested := cdx.Component{
					Name:               "pkg-a",
					Version:            "1.0",
					PackageURL:         "pkg:npm/pkg-a@1.0",
					Type:               cdx.ComponentTypeLibrary,
					ExternalReferences: &[]cdx.ExternalReference{withDigest},
				}
				undigested := cdx.Component{
					Name:       "pkg-b",
					Version:    "1.0",
					PackageURL: "pkg:npm/pkg-b@1.0",
					Type:       cdx.ComponentTypeLibrary,
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://example.com/old.tgz", Type: cdx.ERTypeSourceDistribution},
					},
				}
				components := []cdx.Component{digested, undigested}
				if !digestFirst {
					components = []cdx.Component{undigested, digested}
				}
				bom := &cdx.BOM{Components: &components}

				Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())

				urls := lo.Map(*bom.Components, func(comp cdx.Component, _ int) string {
					return (*comp.ExternalReferences)[0].URL
				})
				Expect(urls).To(ConsistOf("https://example.com/old.tgz", "https://example.com/new.tgz"))
				Expect(*bom.ExternalReferences).To(HaveLen(2))
				Expect(*bom.ExternalReferences).To(ContainElement(withDigest))
				Expect(*bom.ExternalReferences).To(ContainElement(HaveField("URL", "https://example.com/new.tgz")))
			},
			Entry("digested component first", true),
			Entry("undigested component first", false),
		)

		It("keeps a source distribution that already carries a digest", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{
					URL:    "https://example.com/pkg.tgz",
					Kind:   "source-distribution",
					Hashes: []Hash{{Algorithm: "STREEBOG-256", Content: streebog256Content}},
				}, nil
			})

			existing := cdx.ExternalReference{
				URL:    "https://example.com/old.tgz",
				Type:   cdx.ERTypeSourceDistribution,
				Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgorithm("STREEBOG-512"), Value: streebog512Content}},
			}
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{
						Name:               "pkg-a",
						Version:            "1.0",
						PackageURL:         "pkg:npm/pkg-a@1.0",
						Type:               cdx.ComponentTypeLibrary,
						ExternalReferences: &[]cdx.ExternalReference{existing},
					},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(Equal([]cdx.ExternalReference{existing}))
			Expect(*bom.ExternalReferences).To(Equal([]cdx.ExternalReference{existing}))
		})

		It("keeps a vcs reference free of hashes", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{
					URL:    "https://github.com/pkg-a/pkg-a",
					Kind:   "vcs",
					Hashes: []Hash{{Algorithm: "STREEBOG-256", Content: streebog256Content}},
				}, nil
			})

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
			refs := *(*bom.Components)[0].ExternalReferences
			Expect(refs).To(HaveLen(1))
			Expect(refs[0].Hashes).To(BeNil())
		})

		DescribeTable("rejects a source distribution the SBOM validation would fail on",
			func(hashes []Hash, expectedErr string) {
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					return &ResolveResult{URL: "https://example.com/pkg.tgz", Kind: "source-distribution", Hashes: hashes}, nil
				})

				bom := &cdx.BOM{
					Components: &[]cdx.Component{
						{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
					},
				}

				err := enricher.Enrich(ctx, bom)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErr))
				Expect((*bom.Components)[0].ExternalReferences).To(BeNil())
			},
			Entry("no hashes at all", nil,
				`enrich: source distribution has no hashes, expected "STREEBOG-256" or "STREEBOG-512"`),
			Entry("empty hash list", []Hash{},
				`enrich: source distribution has no hashes, expected "STREEBOG-256" or "STREEBOG-512"`),
			Entry("foreign algorithm", []Hash{{Algorithm: "SHA-256", Content: streebog256Content}},
				`enrich: source distribution hash algorithm "SHA-256" is not allowed, expected "STREEBOG-256" or "STREEBOG-512"`),
			Entry("lower-case algorithm name", []Hash{{Algorithm: "Streebog-256", Content: streebog256Content}},
				`enrich: source distribution hash algorithm "Streebog-256" is not allowed`),
			Entry("content of the wrong length", []Hash{{Algorithm: "STREEBOG-512", Content: streebog256Content}},
				`enrich: source distribution hash "STREEBOG-512" has invalid content "`+streebog256Content+`", expected 128 hexadecimal characters`),
			Entry("empty content", []Hash{{Algorithm: "STREEBOG-256", Content: ""}},
				`enrich: source distribution hash "STREEBOG-256" has invalid content "", expected 64 hexadecimal characters`),
			Entry("content that is not hexadecimal", []Hash{{Algorithm: "STREEBOG-256", Content: strings.Repeat("z", 64)}},
				`expected 64 hexadecimal characters`),
			Entry("one foreign algorithm next to a valid one", []Hash{
				{Algorithm: "STREEBOG-256", Content: streebog256Content},
				{Algorithm: "MD5", Content: strings.Repeat("a", 32)},
			}, `enrich: source distribution hash algorithm "MD5" is not allowed`),
		)

		It("uses public Resolve field for custom mock", func() {
			called := false
			enricher := &Enricher{
				Resolve: func(ctx context.Context, purl string) (*ResolveResult, error) {
					called = true
					return &ResolveResult{
						URL:  "https://example.com/" + purl,
						Kind: "vcs",
					}, nil
				},
			}

			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "pkg-a", Version: "1.0", PackageURL: "pkg:npm/pkg-a@1.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			err := enricher.Enrich(ctx, bom)
			Expect(err).NotTo(HaveOccurred())
			Expect(called).To(BeTrue())
		})

		It("Resolve field can be injected via NewEnricher", func() {
			enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{URL: "https://example.com/" + purl, Kind: "vcs"}, nil
			})
			Expect(enricher.Resolve).NotTo(BeNil())
		})
	})

	Describe("ExternalRefPatcher", func() {
		It("calls Enrich via Apply", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21", Type: cdx.ComponentTypeLibrary},
				},
			}

			patcher := &ExternalRefPatcher{enricher: enricher}
			result, err := patcher.Apply(ctx, bom)

			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(bom))
			Expect(result.ExternalReferences).NotTo(BeNil())
		})

		It("returns original BOM on error", func() {
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "unknown", Version: "0.0.0", PackageURL: "pkg:npm/unknown@0.0.0", Type: cdx.ComponentTypeLibrary},
				},
			}

			patcher := &ExternalRefPatcher{enricher: enricher}
			result, err := patcher.Apply(ctx, bom)

			Expect(err).To(HaveOccurred())
			Expect(result).To(Equal(bom))
		})
	})
})
