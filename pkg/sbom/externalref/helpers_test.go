package externalref

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func mockResolver() (http.Handler, *int) {
	calls := new(int)

	type respDef struct {
		status int
		body   string
	}

	respMap := map[string]respDef{
		"pkg:npm/lodash@4.17.21": {
			status: http.StatusOK,
			body:   `{"purl":"pkg:npm/lodash@4.17.21","purl_requested":"pkg:npm/lodash@4.17.21","url":"https://github.com/lodash/lodash","kind":"vcs","confirmed":true,"status":"confirmed","confidence":0.9,"provider":"libraries.io","resolution":"database","sources":[{"kind":"vcs","meta":{"http_status":200,"request_url":"https://libraries.io/api/npm/lodash"},"provider":"libraries.io","picked_url":"https://github.com/lodash/lodash"}]}`,
		},
		"pkg:npm/express@4.18.2": {
			status: http.StatusOK,
			body:   `{"purl":"pkg:npm/express@4.18.2","purl_requested":"pkg:npm/express@4.18.2","url":"https://github.com/expressjs/express","kind":"vcs","confirmed":true,"status":"confirmed","confidence":0.9,"provider":"libraries.io","resolution":"database"}`,
		},
		"pkg:npm/react@18.2.0": {
			status: http.StatusOK,
			body:   `{"purl":"pkg:npm/react@18.2.0","purl_requested":"pkg:npm/react@18.2.0","url":"https://github.com/facebook/react","kind":"vcs","confirmed":true,"status":"confirmed","confidence":0.9,"provider":"libraries.io","resolution":"database"}`,
		},
		"pkg:npm/empty-url-pkg@1.0.0": {
			status: http.StatusOK,
			body:   `{"purl":"pkg:npm/empty-url-pkg@1.0.0","purl_requested":"pkg:npm/empty-url-pkg@1.0.0","url":"","kind":"vcs","confirmed":false,"status":"unresolved"}`,
		},
		"pkg:npm/bad-json@1.0.0": {
			status: http.StatusOK,
			body:   `{invalid json`,
		},
		"pkg:npm/server-error@1.0.0": {
			status: http.StatusInternalServerError,
			body:   `{"error":"internal error"}`,
		},
		"pkg:npm/unknown@0.0.0": {
			status: http.StatusNotFound,
			body:   `{"error":"not found"}`,
		},
	}

	// Verdicts of /api/v1/vcs, keyed by the URL as the SBOM carries it. A URL
	// absent here is one the resolver has never seen: 404, as the real service
	// answers for a key it has no row for.
	vcsMap := map[string]respDef{
		"https://github.com/lodash/lodash": {
			status: http.StatusOK,
			body:   `{"purl":"url:https://github.com/lodash/lodash","purl_requested":"https://github.com/lodash/lodash","url":"https://github.com/lodash/lodash","kind":"vcs","confirmed":true,"status":"confirmed","provider":"url-check","resolution":"database"}`,
		},
		"https://git.example.com/confirmed.git": {
			status: http.StatusOK,
			body:   `{"purl":"url:https://git.example.com/confirmed.git","purl_requested":"https://git.example.com/confirmed.git","url":"https://git.example.com/confirmed.git","kind":"vcs","confirmed":true,"status":"confirmed","provider":"url-check","resolution":"database"}`,
		},
		"https://git.example.com/not-a-repo": {
			status: http.StatusOK,
			body:   `{"purl":"url:https://git.example.com/not-a-repo","purl_requested":"https://git.example.com/not-a-repo","url":"https://git.example.com/not-a-repo","kind":"unknown","confirmed":false,"status":"unconfirmed","provider":"url-check","resolution":"live"}`,
		},
		"https://git.example.com/flaky.git": {
			status: http.StatusInternalServerError,
			body:   `{"error":"internal error"}`,
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++

		if r.URL.Path == "/api/v1/vcs" {
			def, ok := vcsMap[r.URL.Query().Get("url")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
				return
			}
			if def.status == http.StatusOK {
				w.Header().Set("Content-Type", "application/json")
			}
			w.WriteHeader(def.status)
			_, _ = fmt.Fprint(w, def.body)
			return
		}

		if r.URL.Path != "/api/v1/resolve" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}

		purl := r.URL.Query().Get("purl")
		if purl == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing purl"})
			return
		}

		def, ok := respMap[purl]
		if !ok {
			for pattern, pd := range respMap {
				if strings.HasPrefix(purl, strings.TrimSuffix(pattern, "@*")) {
					def = pd
					ok = true
					break
				}
			}
		}

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("no resolution for %s", purl)})
			return
		}

		if def.status != http.StatusOK {
			w.WriteHeader(def.status)
			_, _ = fmt.Fprint(w, def.body)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, def.body)
	})

	return handler, calls
}

// resolveOnly builds an enricher for BOMs that carry no vcs link of their own, so
// a VCS check would be a bug of the code under test rather than of the fixture.
func resolveOnly(resolve func(ctx context.Context, purl string) (*ResolveResult, error)) *Enricher {
	return NewEnricher(resolve, func(_ context.Context, vcsURL string) (*ResolveResult, error) {
		panic(fmt.Sprintf("unexpected VCS check for %q", vcsURL))
	})
}
