package docker_registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type tagsPageSizeFixture struct {
	server *httptest.Server

	mu      sync.Mutex
	queries []url.Values

	tags  []string
	chunk int

	rejectAbove   int
	rejectLimit   int
	rejections    int
	rejectStatus  int
	rejectCode    string
	rejectMessage string
	onReject      func()
}

func newTagsPageSizeFixture(tags ...string) *tagsPageSizeFixture {
	fixture := &tagsPageSizeFixture{tags: tags}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/tags/list") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		query := r.URL.Query()
		fixture.mu.Lock()
		fixture.queries = append(fixture.queries, query)
		fixture.mu.Unlock()

		requestedPageSize, _ := strconv.Atoi(query.Get("n"))
		fixture.mu.Lock()
		reject := fixture.rejectStatus != 0 && requestedPageSize > fixture.rejectAbove && (fixture.rejectLimit == 0 || fixture.rejections < fixture.rejectLimit)
		if reject {
			fixture.rejections++
		}
		fixture.mu.Unlock()
		if reject {
			if fixture.onReject != nil {
				fixture.onReject()
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(fixture.rejectStatus)
			fmt.Fprintf(w, `{"errors":[{"code":%q,"message":%q}]}`, fixture.rejectCode, fixture.rejectMessage)
			return
		}

		fixture.writePage(w, r)
	}))
	return fixture
}

func (fixture *tagsPageSizeFixture) writePage(w http.ResponseWriter, r *http.Request) {
	start := 0
	if last := r.URL.Query().Get("last"); last != "" {
		for i, tag := range fixture.tags {
			if tag == last {
				start = i + 1
				break
			}
		}
	}

	end := len(fixture.tags)
	if fixture.chunk > 0 && start+fixture.chunk < end {
		end = start + fixture.chunk
	}
	page := fixture.tags[start:end]

	w.Header().Set("Content-Type", "application/json")
	if end < len(fixture.tags) {
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?n=%d&last=%s>; rel="next"`, r.Host, r.URL.Path, fixture.chunk, page[len(page)-1]))
	}
	Expect(json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": page})).To(Succeed())
}

func (fixture *tagsPageSizeFixture) requestedPageSizes() []string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	sizes := make([]string, 0, len(fixture.queries))
	for _, query := range fixture.queries {
		sizes = append(sizes, query.Get("n"))
	}
	return sizes
}

type tagsPageSizeTransport struct {
	serverHost string
	inner      http.RoundTripper
}

var _ http.RoundTripper = (*tagsPageSizeTransport)(nil)

func (transport *tagsPageSizeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	routed := req.Clone(req.Context())
	routed.Host = req.URL.Host
	routed.URL.Scheme = "http"
	routed.URL.Host = transport.serverHost
	return transport.inner.RoundTrip(routed)
}

var tagsPageSizeHosts atomic.Int64

func nextTagsPageSizeHost() string {
	return fmt.Sprintf("rejecting-%d.example.test", tagsPageSizeHosts.Add(1))
}

func newTagsPageSizeAPI(fixture *tagsPageSizeFixture) *api {
	registry := newAPI(apiOptions{InsecureRegistry: true})
	registry.httpTransport = &tagsPageSizeTransport{
		serverHost: strings.TrimPrefix(fixture.server.URL, "http://"),
		inner:      registry.httpTransport,
	}
	return registry
}

var _ = Describe("registry tags page size", func() {
	BeforeEach(func() {
		configDir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"auths":{}}`), 0o600)).To(Succeed())
		GinkgoT().Setenv("DOCKER_CONFIG", configDir)
	})

	DescribeTable("requests one page sized for the registry host", func(host, expectedPageSize string) {
		fixture := newTagsPageSizeFixture("latest")
		DeferCleanup(fixture.server.Close)

		tags, err := newTagsPageSizeAPI(fixture).Tags(context.Background(), host+"/repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(tags).To(Equal([]string{"latest"}))
		Expect(fixture.requestedPageSizes()).To(Equal([]string{expectedPageSize}))
	},
		Entry("ordinary registry", "registry.example.test", "1000000"),
		Entry("private ECR", "123456789012.dkr.ecr.eu-central-1.amazonaws.com", "1000"),
		Entry("FIPS ECR", "123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com", "1000"),
		Entry("China ECR", "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", "1000"),
		Entry("public ECR", "public.ecr.aws", "1000"),
		Entry("ECR with an explicit port", "123456789012.dkr.ecr.eu-central-1.amazonaws.com:443", "1000"),
		Entry("host merely containing the ECR domain", "123456789012.dkr.ecr.eu-central-1.amazonaws.com.example.test", "1000000"),
		Entry("host merely containing amazonaws", "registry-amazonaws.com.example.test", "1000000"),
		Entry("host merely prefixed with the public ECR domain", "public.ecr.aws.example.test", "1000000"),
	)

	It("follows the server pagination link without replacing its page size", func() {
		fixture := newTagsPageSizeFixture("a", "b", "c", "d", "e")
		fixture.chunk = 2
		DeferCleanup(fixture.server.Close)

		tags, err := newTagsPageSizeAPI(fixture).Tags(context.Background(), "paginated.example.test/repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(tags).To(Equal([]string{"a", "b", "c", "d", "e"}))
		Expect(fixture.requestedPageSizes()).To(Equal([]string{"1000000", "2", "2"}))
	})

	DescribeTable("retries with the fallback page size only on an explicit page size rejection", func(status int, code, message string, expectFallback bool) {
		fixture := newTagsPageSizeFixture("latest")
		fixture.rejectAbove = 1000
		fixture.rejectStatus, fixture.rejectCode, fixture.rejectMessage = status, code, message
		if status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
			fixture.rejectLimit = 1
		}
		DeferCleanup(fixture.server.Close)

		tags, err := newTagsPageSizeAPI(fixture).Tags(context.Background(), nextTagsPageSizeHost()+"/repo")
		if expectFallback {
			Expect(err).NotTo(HaveOccurred())
			Expect(tags).To(Equal([]string{"latest"}))
			Expect(fixture.requestedPageSizes()).To(Equal([]string{"1000000", "1000"}))
			return
		}

		if fixture.rejectLimit == 0 && status != http.StatusNotFound {
			Expect(err).To(HaveOccurred())
			Expect(tags).To(BeEmpty())
		}
		Expect(fixture.requestedPageSizes()).NotTo(BeEmpty())
		Expect(fixture.requestedPageSizes()).To(HaveEach("1000000"))
	},
		Entry("OCI pagination code", http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "invalid number of tags requested", true),
		Entry("OCI pagination code with an unprocessable status", http.StatusUnprocessableEntity, "PAGINATION_NUMBER_INVALID", "invalid number of tags requested", true),
		Entry("ECR maxResults rejection", http.StatusBadRequest, "UNSUPPORTED", "Invalid parameter at 'maxResults' failed to satisfy constraint: 'Member must have value less than or equal to 1000'", true),
		Entry("ECR maxResults rejection in another casing and bound", http.StatusBadRequest, "UNSUPPORTED", "invalid parameter at 'maxresults' failed to satisfy constraint: 'member must have value less than or equal to 100'", true),
		Entry("unsupported operation", http.StatusBadRequest, "UNSUPPORTED", "The operation is unsupported", false),
		Entry("invalid name", http.StatusBadRequest, "NAME_INVALID", "invalid repository name", false),
		Entry("unauthorized", http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", false),
		Entry("denied", http.StatusForbidden, "DENIED", "requested access to the resource is denied", false),
		Entry("unknown repository", http.StatusNotFound, "NAME_UNKNOWN", "repository name not known to registry", false),
		Entry("too many requests", http.StatusTooManyRequests, "TOOMANYREQUESTS", "too many requests", false),
		Entry("server error", http.StatusInternalServerError, "UNKNOWN", "internal error", false),
	)

	It("keeps the fallback page size for the rejecting host only", func() {
		rejecting := newTagsPageSizeFixture("latest")
		rejecting.rejectAbove = 1000
		rejecting.rejectStatus, rejecting.rejectCode, rejecting.rejectMessage = http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "invalid number of tags requested"
		DeferCleanup(rejecting.server.Close)

		const host = "remembering.example.test"
		_, err := newTagsPageSizeAPI(rejecting).Tags(context.Background(), host+"/repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(rejecting.requestedPageSizes()).To(Equal([]string{"1000000", "1000"}))

		_, err = newTagsPageSizeAPI(rejecting).Tags(context.Background(), host+"/other-repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(rejecting.requestedPageSizes()).To(Equal([]string{"1000000", "1000", "1000"}))

		other := newTagsPageSizeFixture("latest")
		DeferCleanup(other.server.Close)
		_, err = newTagsPageSizeAPI(other).Tags(context.Background(), "unrelated.example.test/repo")
		Expect(err).NotTo(HaveOccurred())
		Expect(other.requestedPageSizes()).To(Equal([]string{"1000000"}))
	})

	It("fails with the fallback rejection when the fallback page size is rejected too", func() {
		fixture := newTagsPageSizeFixture("latest")
		fixture.rejectStatus, fixture.rejectCode, fixture.rejectMessage = http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "invalid number of tags requested"
		DeferCleanup(fixture.server.Close)

		tags, err := newTagsPageSizeAPI(fixture).Tags(context.Background(), "always-rejecting.example.test/repo")
		Expect(tags).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("PAGINATION_NUMBER_INVALID")))
		Expect(fixture.requestedPageSizes()).To(Equal([]string{"1000000", "1000"}))
	})

	It("reads tags concurrently while the fallback page size is recorded", func() {
		fixture := newTagsPageSizeFixture("latest")
		fixture.rejectAbove = 1000
		fixture.rejectStatus, fixture.rejectCode, fixture.rejectMessage = http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "invalid number of tags requested"
		DeferCleanup(fixture.server.Close)

		registry := newTagsPageSizeAPI(fixture)
		var readers sync.WaitGroup
		results := make(chan error, 8)
		for i := range 8 {
			readers.Add(1)
			go func() {
				defer readers.Done()
				_, err := registry.Tags(context.Background(), fmt.Sprintf("concurrent.example.test/repo-%d", i))
				results <- err
			}()
		}
		readers.Wait()
		close(results)
		for err := range results {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("carries the caller cancellation into the fallback request", func() {
		fixture := newTagsPageSizeFixture("latest")
		fixture.rejectAbove = 1000
		fixture.rejectStatus, fixture.rejectCode, fixture.rejectMessage = http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "invalid number of tags requested"
		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		fixture.onReject = cancel
		DeferCleanup(fixture.server.Close)

		_, err := newTagsPageSizeAPI(fixture).Tags(ctx, "canceled.example.test/repo")
		Expect(err).To(MatchError(context.Canceled))
		Expect(fixture.requestedPageSizes()).To(Equal([]string{"1000000"}))
	})
})
