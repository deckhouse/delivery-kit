package docker

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/docker/cli/cli/command"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"golang.org/x/net/context"

	"github.com/werf/werf/v2/pkg/opstats"
)

// cliDaemonContext points the docker CLI at addr and returns a context carrying a CLI bound
// to it, so that both the API wrappers and the commands executed through the CLI (pull,
// push, build, run) reach the fake daemon instead of a real one.
func cliDaemonContext(addr string) context.Context {
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION", "DOCKER_CONTENT_TRUST", "WERF_DEBUG_DOCKER"} {
		ginkgo.GinkgoT().Setenv(key, "")
	}
	ginkgo.GinkgoT().Setenv("DOCKER_HOST", "tcp://"+addr)
	gomega.Expect(InitDockerConfig(InitOptions{DockerConfigDir: ginkgo.GinkgoT().TempDir()})).To(gomega.Succeed())

	c, err := newDockerCli([]command.CLIOption{
		command.WithInputStream(io.NopCloser(strings.NewReader(""))),
		command.WithOutputStream(io.Discard),
		command.WithErrorStream(io.Discard),
		command.WithContentTrust(false),
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	ginkgo.DeferCleanup(c.Client().Close)

	return context.WithValue(context.Background(), ctxDockerCliKey, c)
}

func newDaemonServer(handler http.Handler) string {
	server := httptest.NewServer(handler)
	ginkgo.DeferCleanup(server.Close)
	return server.Listener.Addr().String()
}

func observedDaemonContext(handler http.Handler) (context.Context, *opstats.Collector) {
	collector := opstats.NewCollector()
	return opstats.NewContext(cliDaemonContext(newDaemonServer(handler)), collector), collector
}

func writePing(w http.ResponseWriter) {
	w.Header().Set("API-Version", "1.41")
	w.Header().Set("OSType", "linux")
}

func respondJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			writePing(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, body); err != nil {
			panic(err)
		}
	}
}

func respondError(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/_ping") {
		writePing(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	if _, err := io.WriteString(w, `{"message":"daemon failure"}`); err != nil {
		panic(err)
	}
}

// newMissingImageDaemonServer returns the address of a daemon rejecting every request as
// not found, an error the cli retry helper treats as permanent, so a command reaching it
// fails after a single attempt.
func newMissingImageDaemonServer() string {
	return newDaemonServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			writePing(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if _, err := io.WriteString(w, `{"message":"No such image: img"}`); err != nil {
			panic(err)
		}
	}))
}

// newDelayedCreateServer returns the address of a daemon which stalls the container create
// request and then rejects it, so that a run which never reaches container start still takes
// at least delay.
func newDelayedCreateServer(delay time.Duration) string {
	return newDaemonServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			writePing(w)
			return
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if _, err := io.WriteString(w, `{"message":"No such image: img"}`); err != nil {
			panic(err)
		}
	}))
}

func operationCount(collector *opstats.Collector, op opstats.Operation) int {
	for _, summary := range collector.Summary() {
		if summary.Operation == op {
			return summary.Count
		}
	}
	return 0
}
