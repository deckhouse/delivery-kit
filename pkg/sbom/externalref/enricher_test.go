package externalref

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/logging"
)

var _ = Describe("Enricher", func() {
	var ts *httptest.Server
	var service *Service
	var enricher *Enricher
	var ctx context.Context

	BeforeEach(func() {
		handler, _ := mockResolver()
		ts = httptest.NewServer(handler)
		service = NewService(ServiceConfig{ServerURL: ts.URL})
		enricher = NewEnricher(service.Resolve, service.CheckVCS)
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
					Expect(errMsg).To(ContainSubstring("no-purl-lib"))
					Expect(errMsg).To(ContainSubstring("has no purl"))
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

		It("error string contains component details format: '- <name> (<purl>): <error>'", func() {
			enricher := resolveOnly(func(ctx context.Context, purl string) (*ResolveResult, error) {
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
			Expect(errMsg).To(ContainSubstring("- component: pkg-a: resolve failed"))
			Expect(errMsg).To(ContainSubstring("- component: pkg-b: resolve failed"))
		})

		It("uses public Resolve field for custom mock", func() {
			called := false
			enricher := &Enricher{
				Resolve: func(ctx context.Context, purl string) (*ResolveResult, error) {
					called = true
					return &ResolveResult{
						URL:  "https://example.com/" + purl,
						Kind: "website",
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

		Describe("component with a vcs link of its own", func() {
			withVCS := func(name, purl, vcsURL string) cdx.Component {
				return cdx.Component{
					Name:               name,
					Version:            "1.0",
					PackageURL:         purl,
					Type:               cdx.ComponentTypeLibrary,
					ExternalReferences: &[]cdx.ExternalReference{{URL: vcsURL, Type: cdx.ERTypeVCS}},
				}
			}

			It("verifies the link and never resolves the purl when the resolver confirms it", func() {
				var resolved []string
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					resolved = append(resolved, purl)
					return nil, fmt.Errorf("resolve: %w", ErrEmptyURL)
				}, service.CheckVCS)
				// The purl names a package index the resolver has never heard of: the
				// case of a build whose packages come from an unpublished catalog.
				bom := &cdx.BOM{Components: &[]cdx.Component{
					withVCS("libssl3", "pkg:generic/libssl3@3.6.2?containerfactoryversion=feature-branch", "https://git.example.com/confirmed.git"),
				}}

				Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
				Expect(resolved).To(BeEmpty())

				refs := *(*bom.Components)[0].ExternalReferences
				Expect(refs).To(Equal([]cdx.ExternalReference{{URL: "https://git.example.com/confirmed.git", Type: cdx.ERTypeVCS}}))
				Expect(*bom.ExternalReferences).To(Equal(refs))
			})

			It("verifies a shared link once for every component carrying it", func() {
				handler, calls := mockResolver()
				ts := httptest.NewServer(handler)
				defer ts.Close()
				svc := NewService(ServiceConfig{ServerURL: ts.URL})
				enricher := NewEnricher(svc.Resolve, svc.CheckVCS)

				bom := &cdx.BOM{Components: &[]cdx.Component{
					withVCS("libssl3", "pkg:generic/libssl3@3.6.2?containerfactoryversion=x", "https://git.example.com/confirmed.git"),
					withVCS("libcrypto3", "pkg:generic/libcrypto3@3.6.2?containerfactoryversion=x", "https://git.example.com/confirmed.git"),
					withVCS("libssl3", "pkg:generic/libssl3@3.6.2?containerfactoryversion=y", "https://git.example.com/confirmed.git"),
				}}

				Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())
				Expect(*calls).To(Equal(1))
			})

			DescribeTable("falls back to purl resolution when the link is not confirmed",
				func(vcsURL string) {
					bom := &cdx.BOM{Components: &[]cdx.Component{
						withVCS("lodash", "pkg:npm/lodash@4.17.21", vcsURL),
					}}

					Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())

					refs := *(*bom.Components)[0].ExternalReferences
					Expect(refs).To(HaveLen(1), "the unconfirmed link must not stay next to the resolved one")
					Expect(refs[0].URL).To(Equal("https://github.com/lodash/lodash"))
					Expect(refs[0].Type).To(Equal(cdx.ERTypeVCS))
				},
				Entry("resolver reports the link is not a repository", "https://git.example.com/not-a-repo"),
				Entry("resolver has never seen the link", "https://git.example.com/never-seen.git"),
			)

			It("fails with both causes when neither the link nor the purl is confirmed", func() {
				bom := &cdx.BOM{Components: &[]cdx.Component{
					withVCS("svace", "pkg:generic/svace@6.0?containerfactoryversion=feature-branch", "https://git.example.com/not-a-repo"),
				}}

				err := enricher.Enrich(ctx, bom)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(`component: svace: vcs link "https://git.example.com/not-a-repo" not confirmed: resolver reports kind "unknown"; resolve "pkg:generic/svace@6.0?containerfactoryversion=feature-branch": unexpected status 404`))
				Expect(*(*bom.Components)[0].ExternalReferences).To(HaveLen(1), "a failed enrichment leaves the component as it was")
			})

			It("treats a resolver failure on the link check as terminal, not as an unconfirmed link", func() {
				var resolved []string
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					resolved = append(resolved, purl)
					return &ResolveResult{URL: "https://github.com/x/y", Kind: "vcs"}, nil
				}, func(ctx context.Context, vcsURL string) (*ResolveResult, error) {
					return nil, &ClassifiedError{Class: FailureClassInfra, Err: fmt.Errorf("check vcs: unexpected status 500")}
				})
				bom := &cdx.BOM{Components: &[]cdx.Component{
					withVCS("lodash", "pkg:npm/lodash@4.17.21", "https://git.example.com/flaky.git"),
				}}

				err := enricher.Enrich(ctx, bom)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unexpected status 500"))
				Expect(resolved).To(BeEmpty())
			})

			It("drops every unconfirmed vcs link of a foreign SBOM component that carries more than one", func() {
				bom := &cdx.BOM{Components: &[]cdx.Component{{
					Name:       "lodash",
					Version:    "1.0",
					PackageURL: "pkg:npm/lodash@4.17.21",
					Type:       cdx.ComponentTypeLibrary,
					ExternalReferences: &[]cdx.ExternalReference{
						{URL: "https://git.example.com/not-a-repo", Type: cdx.ERTypeVCS},
						{URL: "https://git.example.com/another-unverified.git", Type: cdx.ERTypeVCS},
					},
				}}}

				Expect(enricher.Enrich(ctx, bom)).NotTo(HaveOccurred())

				refs := *(*bom.Components)[0].ExternalReferences
				Expect(refs).To(HaveLen(1))
				Expect(refs[0].URL).To(Equal("https://github.com/lodash/lodash"))
			})

			It("stays terminal when the build is canceled during the backoff of a failing link check", func() {
				var resolved []string
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					resolved = append(resolved, purl)
					return &ResolveResult{URL: "https://github.com/x/y", Kind: "vcs"}, nil
				}, service.CheckVCS)
				bom := &cdx.BOM{Components: &[]cdx.Component{
					withVCS("lodash", "pkg:npm/lodash@4.17.21", "https://git.example.com/flaky.git"),
				}}
				cancelCtx, cancel := context.WithCancelCause(ctx)
				time.AfterFunc(200*time.Millisecond, func() { cancel(errors.New("SIBLING IMAGE FAILURE REPORT")) })

				err := enricher.Enrich(cancelCtx, bom)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context canceled"))
				Expect(err.Error()).NotTo(ContainSubstring("SIBLING IMAGE FAILURE REPORT"))
				Expect(err.Error()).NotTo(ContainSubstring("not confirmed"))
				Expect(resolved).To(BeEmpty())
			})

			It("surfaces a tripped breaker on the link check through the usual sentinel", func() {
				enricher := NewEnricher(func(ctx context.Context, purl string) (*ResolveResult, error) {
					return &ResolveResult{URL: "https://github.com/x/y", Kind: "vcs"}, nil
				}, func(ctx context.Context, vcsURL string) (*ResolveResult, error) {
					return nil, ErrResolverUnavailable
				})
				bom := &cdx.BOM{Components: &[]cdx.Component{
					withVCS("lodash", "pkg:npm/lodash@4.17.21", "https://git.example.com/confirmed.git"),
				}}

				err := enricher.Enrich(ctx, bom)
				Expect(errors.Is(err, ErrResolverUnavailable)).To(BeTrue())
			})
		})

		It("Resolve field can be injected via NewEnricher", func() {
			enricher := resolveOnly(func(ctx context.Context, purl string) (*ResolveResult, error) {
				return &ResolveResult{URL: "https://example.com/" + purl, Kind: "website"}, nil
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
