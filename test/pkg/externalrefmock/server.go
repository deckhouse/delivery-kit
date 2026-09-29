package externalrefmock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// SourceDistributionPURLPrefix selects the purls answered with a source
// distribution instead of a repository. The real resolver falls back to the
// published archive when it cannot confirm a repository for a package, and npm
// is where that happens often enough to be worth reproducing: a component then
// carries a source-distribution link as its only reference, which is the case
// the ISPRAS schema requires a digest for.
const SourceDistributionPURLPrefix = "pkg:npm/"

// SourceDistributionHash is the digest the resolver reports next to a source
// distribution: GOST R 34.11-2012, in the upper-case spelling the ISPRAS schema
// accepts.
var SourceDistributionHash = Hash{
	Algorithm: "STREEBOG-256",
	Content:   "4559fe98d002ff12ab69dafaf495d49ab7bfe14fd4408bf733dd99b3056c65bf",
}

var (
	mu     sync.Mutex
	server *httptest.Server
)

type Response struct {
	PURL   string `json:"purl"`
	URL    string `json:"url"`
	Kind   string `json:"kind"`
	Hashes []Hash `json:"hashes,omitempty"`
}

type Hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

func Start() *httptest.Server {
	mu.Lock()
	defer mu.Unlock()
	if server == nil {
		server = httptest.NewServer(http.HandlerFunc(handler))
	}
	return server
}

func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if server != nil {
		server.Close()
		server = nil
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	purl := r.URL.Query().Get("purl")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response(purl))
}

func response(purl string) Response {
	if strings.HasPrefix(purl, SourceDistributionPURLPrefix) {
		return Response{
			PURL:   purl,
			URL:    SourceDistributionURL(purl),
			Kind:   "source-distribution",
			Hashes: []Hash{SourceDistributionHash},
		}
	}

	return Response{
		PURL: purl,
		URL:  "https://github.com/example/repo",
		Kind: "vcs",
	}
}

// SourceDistributionURL is the archive URL the mock reports for a purl, shaped
// like the npm registry one so a test can assert on it. A scoped package keeps
// its "@scope/" prefix, so the version is taken from the last separator.
func SourceDistributionURL(purl string) string {
	coordinates, _, _ := strings.Cut(strings.TrimPrefix(purl, SourceDistributionPURLPrefix), "?")

	name, version := coordinates, ""
	if at := strings.LastIndex(coordinates, "@"); at > 0 {
		name, version = coordinates[:at], coordinates[at+1:]
	}

	return "https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz"
}
