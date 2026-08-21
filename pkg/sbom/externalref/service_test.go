package externalref

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/logging"
	"github.com/werf/werf/v2/pkg/werf"
)

var _ = Describe("Service", func() {
	var ts *httptest.Server
	var calls *int
	var service *Service
	var ctx context.Context

	BeforeEach(func() {
		handler, c := mockResolver()
		calls = c
		ts = httptest.NewServer(handler)
		service = NewService(ServiceConfig{ServerURL: ts.URL})
		ctx = logging.WithLogger(context.Background())
	})

	AfterEach(func() {
		ts.Close()
	})

	Describe("default constants", func() {
		It("has default HTTP client timeout of 5 seconds", func() {
			Expect(defaultServiceTimeout).To(Equal(5 * time.Second))
		})

		It("has MaxElapsedTime of 10 seconds", func() {
			Expect(defaultMaxElapsedTime).To(Equal(10 * time.Second))
		})
	})

	Describe("Resolve", func() {
		type resolveCase struct {
			purl  string
			check func(*ResolveResult, error)
		}

		DescribeTable("returns expected result",
			func(c resolveCase) {
				result, err := service.Resolve(ctx, c.purl)
				c.check(result, err)
			},
			Entry("resolves lodash to VCS URL", resolveCase{
				purl: "pkg:npm/lodash@4.17.21",
				check: func(r *ResolveResult, err error) {
					Expect(err).NotTo(HaveOccurred())
					Expect(r.URL).To(Equal("https://github.com/lodash/lodash"))
					Expect(r.Kind).To(Equal("vcs"))
					Expect(r.Confirmed).To(BeTrue())
					Expect(r.PURL).To(Equal("pkg:npm/lodash@4.17.21"))
				},
			}),
			Entry("resolves express to VCS URL", resolveCase{
				purl: "pkg:npm/express@4.18.2",
				check: func(r *ResolveResult, err error) {
					Expect(err).NotTo(HaveOccurred())
					Expect(r.URL).To(Equal("https://github.com/expressjs/express"))
					Expect(r.Kind).To(Equal("vcs"))
					Expect(r.Confirmed).To(BeTrue())
				},
			}),
			Entry("returns error on 404", resolveCase{
				purl: "pkg:npm/unknown@0.0.0",
				check: func(r *ResolveResult, err error) {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("unexpected status 404"))
				},
			}),
			Entry("returns error on empty URL in response", resolveCase{
				purl: "pkg:npm/empty-url-pkg@1.0.0",
				check: func(r *ResolveResult, err error) {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(ErrEmptyURL.Error()))
				},
			}),
			Entry("returns error on bad JSON", resolveCase{
				purl: "pkg:npm/bad-json@1.0.0",
				check: func(r *ResolveResult, err error) {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("parse response"))
				},
			}),
		)

		It("returns error on server error (without retry)", func() {
			timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			noRetryService := NewService(ServiceConfig{
				ServerURL:  ts.URL,
				HTTPClient: &http.Client{Timeout: 30 * time.Second},
			})
			_, err := noRetryService.Resolve(timeoutCtx, "pkg:npm/server-error@1.0.0")
			Expect(err).To(HaveOccurred())
		})

		It("sends werf User-Agent header", func() {
			var capturedUA string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedUA = r.UserAgent()
				w.WriteHeader(http.StatusNotFound)
			})
			uaTS := httptest.NewServer(handler)
			defer uaTS.Close()

			uaService := NewService(ServiceConfig{ServerURL: uaTS.URL})
			_, _ = uaService.Resolve(ctx, "pkg:npm/lodash@4.17.21")

			Expect(capturedUA).To(Equal(werf.UserAgent))
		})

		It("counts resolve calls", func() {
			_, _ = service.Resolve(ctx, "pkg:npm/lodash@4.17.21")
			_, _ = service.Resolve(ctx, "pkg:npm/express@4.18.2")
			Expect(*calls).To(Equal(2))
		})
	})

	Describe("failure classification", func() {
		resolveOnce := func(purl string) error {
			_, err := service.doResolve(ctx, ts.URL+"/api/v1/resolve?purl="+purl, purl)
			return err
		}

		classOf := func(err error) FailureClass {
			var classified *ClassifiedError
			Expect(errors.As(err, &classified)).To(BeTrue(), "error must carry a FailureClass: %v", err)
			return classified.Class
		}

		DescribeTable("classifies single resolution attempts",
			func(purl string, expected FailureClass) {
				err := resolveOnce(purl)
				Expect(err).To(HaveOccurred())
				Expect(classOf(err)).To(Equal(expected))
			},
			Entry("HTTP 404 is a content failure", "pkg:npm/unknown@0.0.0", FailureClassContent),
			Entry("empty URL in response is a content failure", "pkg:npm/empty-url-pkg@1.0.0", FailureClassContent),
			Entry("unparseable response is a content failure", "pkg:npm/bad-json@1.0.0", FailureClassContent),
			Entry("HTTP 500 is an infrastructure failure", "pkg:npm/server-error@1.0.0", FailureClassInfra),
		)

		It("classifies transport errors as infrastructure failures", func() {
			deadTS := httptest.NewServer(http.NotFoundHandler())
			deadTS.Close()

			deadService := NewService(ServiceConfig{ServerURL: deadTS.URL})
			_, err := deadService.doResolve(ctx, deadTS.URL+"/api/v1/resolve?purl=pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21")
			Expect(err).To(HaveOccurred())
			Expect(classOf(err)).To(Equal(FailureClassInfra))
		})

		It("surfaces the classification through the Resolve retry loop", func() {
			_, err := service.Resolve(ctx, "pkg:npm/unknown@0.0.0")
			Expect(err).To(HaveOccurred())
			Expect(classOf(err)).To(Equal(FailureClassContent))
		})
	})

	Describe("resolver breaker integration", func() {
		It("records infrastructure failures per attempt and short-circuits once tripped", func() {
			breaker := NewResolverBreaker(ts.URL)
			breakerService := NewService(ServiceConfig{ServerURL: ts.URL, Breaker: breaker})

			for i := 0; i < resolverBreakerThreshold; i++ {
				_, err := breakerService.doResolve(ctx, ts.URL+"/api/v1/resolve?purl=pkg:npm/server-error@1.0.0", "pkg:npm/server-error@1.0.0")
				Expect(err).To(HaveOccurred())
			}

			callsBefore := *calls
			_, err := breakerService.Resolve(ctx, "pkg:npm/lodash@4.17.21")
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrResolverUnavailable)).To(BeTrue())
			Expect(*calls).To(Equal(callsBefore), "tripped breaker must not produce HTTP requests")
		})

		It("aborts an in-flight retry loop when the breaker trips", func() {
			breaker := NewResolverBreaker(ts.URL)
			breakerService := NewService(ServiceConfig{ServerURL: ts.URL, Breaker: breaker})

			for i := 0; i < resolverBreakerThreshold; i++ {
				breaker.RecordFailure(FailureClassInfra, &ClassifiedError{Class: FailureClassInfra, Err: errors.New("connection refused")})
			}

			callsBefore := *calls
			_, err := breakerService.doResolve(ctx, ts.URL+"/api/v1/resolve?purl=pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21")
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrResolverUnavailable)).To(BeTrue())
			Expect(*calls).To(Equal(callsBefore))
		})

		It("resets the breaker counter on successful resolution", func() {
			breaker := NewResolverBreaker(ts.URL)
			breakerService := NewService(ServiceConfig{ServerURL: ts.URL, Breaker: breaker})

			for i := 0; i < resolverBreakerThreshold-1; i++ {
				_, err := breakerService.doResolve(ctx, ts.URL+"/api/v1/resolve?purl=pkg:npm/server-error@1.0.0", "pkg:npm/server-error@1.0.0")
				Expect(err).To(HaveOccurred())
			}

			_, err := breakerService.Resolve(ctx, "pkg:npm/lodash@4.17.21")
			Expect(err).NotTo(HaveOccurred())

			for i := 0; i < resolverBreakerThreshold-1; i++ {
				_, err := breakerService.doResolve(ctx, ts.URL+"/api/v1/resolve?purl=pkg:npm/server-error@1.0.0", "pkg:npm/server-error@1.0.0")
				Expect(err).To(HaveOccurred())
			}
			Expect(breaker.Allow()).To(Succeed())
		})

		It("works without a breaker configured", func() {
			plainService := NewService(ServiceConfig{ServerURL: ts.URL})
			_, err := plainService.Resolve(ctx, "pkg:npm/lodash@4.17.21")
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
