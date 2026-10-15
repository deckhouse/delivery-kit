package e2e_build_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/utils"
)

func startBuildHTTPFixture(ctx context.Context, content []byte) string {
	host := os.Getenv("WERF_TEST_HTTP_HOST_IP")
	if host == "" && runtime.GOOS == "linux" {
		host = strings.TrimSpace(utils.SucceedCommandOutputString(ctx, "", "docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"))
		gomega.Expect(host).NotTo(gomega.BeEmpty(), "set WERF_TEST_HTTP_HOST_IP to a non-primary local address reachable by the builders")
	}
	if host == "" {
		connection, err := (&net.Dialer{}).DialContext(ctx, "udp4", "192.0.2.1:80")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		host = connection.LocalAddr().(*net.UDPAddr).IP.String()
		gomega.Expect(connection.Close()).To(gomega.Succeed())
	}
	address := net.ParseIP(host)
	gomega.Expect(address).NotTo(gomega.BeNil(), "WERF_TEST_HTTP_HOST_IP must be a local IP reachable by the builders")
	gomega.Expect(address.IsGlobalUnicast() && !address.IsLoopback()).To(gomega.BeTrue())
	listener, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.ServeContent(writer, request, "fixture", time.Unix(1, 0), bytes.NewReader(content))
	}))
	gomega.Expect(server.Listener.Close()).To(gomega.Succeed())
	server.Listener = listener
	server.Start()
	ginkgo.DeferCleanup(server.Close)
	return server.URL
}

func buildFixtureArchive() []byte {
	var archive bytes.Buffer
	compressed := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressed)
	content := []byte("module github.com/werf/werf\n")
	gomega.Expect(writer.WriteHeader(&tar.Header{
		Name: "fixture/go.mod",
		Mode: 0o644,
		Size: int64(len(content)),
	})).To(gomega.Succeed())
	_, err := writer.Write(content)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	gomega.Expect(compressed.Close()).To(gomega.Succeed())
	return archive.Bytes()
}

type gitOwnershipTestOptions struct {
	setupEnvOptions
	OwnerFirst bool
}

func (opts gitOwnershipTestOptions) env() setupEnvOptions {
	return opts.setupEnvOptions
}

const (
	gitOwnershipDefaultImage = "img-default"
	gitOwnershipOwnedImage   = "img-owned"
)

func gitOwnershipChecks(ownerGroup, fileContent string, extraPaths ...string) []string {
	checks := []string{
		fmt.Sprintf("test %q = \"$(cat /app/file)\"", fileContent),
		fmt.Sprintf("test %q = \"$(stat -c %%u:%%g /app/file)\"", ownerGroup),
		"test -L /app/link",
		fmt.Sprintf("test %q = \"$(stat -c %%u:%%g /app/link)\"", ownerGroup),
		`test "3001:3002" = "$(stat -c %u:%g /outside/target)"`,
		`test "4001:4002" = "$(stat -c %u:%g /app/base-file)"`,
		`test "installed" = "$(cat /sentinel)"`,
		`test "0:0" = "$(stat -c %u:%g /sentinel)"`,
	}

	for _, extraPath := range extraPaths {
		checks = append(checks,
			fmt.Sprintf("test -e %s", extraPath),
			fmt.Sprintf("test %q = \"$(stat -c %%u:%%g %s)\"", ownerGroup, extraPath),
		)

		for dir := path.Dir(extraPath); dir != "/app" && dir != "/"; dir = path.Dir(dir) {
			checks = append(checks,
				fmt.Sprintf("test -d %s", dir),
				fmt.Sprintf("test %q = \"$(stat -c %%u:%%g %s)\"", ownerGroup, dir),
			)
		}
	}

	return checks
}
