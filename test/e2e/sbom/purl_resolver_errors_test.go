package e2e_build_test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("PURL resolver errors", Label("e2e", "sbom", "simple", "purl-resolver-errors"), func() {
	var mockServer *httptest.Server

	BeforeEach(func() {
		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			purl := r.URL.Query().Get("purl")
			mockResponse(w, purl)
		}))
	})

	AfterEach(func() {
		mockServer.Close()
	})

	DescribeTable("three-image build with mixed PURL resolution outcomes",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			// Override the external refs server URL with our custom mock that returns failures
			// for specific packages (curl, openssl) and success for others (jq).
			SuiteData.Stubs.SetEnv("WERF_EXTERNAL_REFS_SERVER_URL", mockServer.URL)

			repoDirname := "repo_purl_resolver_errors"
			SuiteData.InitTestRepo(ctx, repoDirname, "purl_resolver_errors")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "purl-errors-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			out, err := werfProject.BuildWithErr(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					Envs: builderEnv,
				},
			})

			Expect(err).To(HaveOccurred(), "build should fail with aggregated PURL error")

			By("build output contains resolve external references format")
			Expect(out).To(ContainSubstring("resolve external references"))

			By("error has hierarchical format: image names prefixed with '(image)'")
			Expect(out).To(ContainSubstring("  - image: image-fail-all"))
			Expect(out).To(ContainSubstring("  - image: image-fail-partial"))

			By("error lists component names of failing packages with PURL and error details")
			Expect(out).To(ContainSubstring(`    - component: curl: resolve "pkg:generic/curl@8.12.1`))
			Expect(out).To(ContainSubstring(`    - component: openssl: resolve "pkg:generic/openssl@3.6.2`))
			Expect(out).To(ContainSubstring("unexpected status 404"))

			By("aggregated error does NOT contain (image) image-ok")
			Expect(out).NotTo(ContainSubstring("image: image-ok"))
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		XEntry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)
})

func mockResponse(w http.ResponseWriter, purl string) {
	if strings.Contains(purl, "curl") || strings.Contains(purl, "openssl") {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"package not found"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"purl":"` + purl + `","url":"https://example.com/repo","kind":"vcs"}`))
}
