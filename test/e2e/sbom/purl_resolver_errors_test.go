package e2e_build_test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("PURL resolver errors", Label("e2e", "sbom", "simple", "purl-resolver-errors"), func() {
	var mockServer *httptest.Server

	BeforeEach(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
			mockResolveResponse(w, r.URL.Query().Get("purl"))
		})
		mux.HandleFunc("/api/v1/vcs", func(w http.ResponseWriter, r *http.Request) {
			mockVCSResponse(w, r.URL.Query().Get("url"))
		})
		mockServer = httptest.NewServer(mux)
	})

	AfterEach(func() {
		mockServer.Close()
	})

	It("three-image build with mixed PURL resolution outcomes", func(ctx SpecContext) {
		setupSbomBuildEnv()

		// The mock does not vouch for the repository links curl and openssl carry and
		// fails their purls, so both go through the vcs check and the purl fallback and
		// end up in the aggregated error; every other component is confirmed by its link.
		SuiteData.Stubs.SetEnv("WERF_EXTERNAL_REFS_SERVER_URL", mockServer.URL)

		repoDirname := "repo_purl_resolver_errors"
		SuiteData.InitTestRepo(ctx, repoDirname, "purl_resolver_errors")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		out, err := werfProject.BuildWithErr(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{},
		})

		Expect(err).To(HaveOccurred(), "build should fail with aggregated PURL error")

		By("build output contains resolve external references format")
		Expect(out).To(ContainSubstring("resolve external references"))

		By("error has hierarchical format: image names prefixed with '(image)'")
		Expect(out).To(ContainSubstring("  - image: image-fail-all"))
		Expect(out).To(ContainSubstring("  - image: image-fail-partial"))

		By("error lists component names of failing packages with PURL and error details")
		Expect(out).To(ContainSubstring(`    - component: curl (pkg:generic/curl@8.12.1`))
		Expect(out).To(ContainSubstring(`    - component: openssl (pkg:generic/openssl@3.6.2`))
		Expect(out).To(ContainSubstring("resolve: unexpected status 404"))

		By("aggregated error does NOT contain (image) image-ok")
		Expect(out).NotTo(ContainSubstring("image: image-ok"))
	})
})

func mockResolveResponse(w http.ResponseWriter, purl string) {
	installedByFixture := strings.Contains(purl, "containerfactoryversion=")
	if installedByFixture && (strings.Contains(purl, "curl") || strings.Contains(purl, "openssl")) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"package not found"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"purl":"` + purl + `","url":"https://example.com/repo","kind":"vcs"}`))
}

func mockVCSResponse(w http.ResponseWriter, vcsURL string) {
	kind := "vcs"
	if strings.Contains(vcsURL, "github.com/curl/curl") || strings.Contains(vcsURL, "github.com/openssl/openssl") {
		kind = "unknown"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"url":"` + vcsURL + `","kind":"` + kind + `"}`))
}
