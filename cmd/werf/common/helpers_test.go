package common

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/registry"
	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/storage"
)

var _ storage.StagesStorage = (*secondaryTestPrimaryStorage)(nil)

type secondaryTestPrimaryStorage struct {
	storage.StagesStorage
	address string
}

func (s *secondaryTestPrimaryStorage) Address() string {
	return s.address
}

var _ container_backend.ContainerBackend = (*secondaryTestContainerBackend)(nil)

type secondaryTestContainerBackend struct {
	container_backend.ContainerBackend
}

func secondaryTestCmdData(secondaryRepos []string) *CmdData {
	secondaryTestIsolateEnv()
	return &CmdData{
		InsecureRegistry:       boolPtr(false),
		SkipTlsVerifyRegistry:  boolPtr(true),
		SecondaryStagesStorage: &secondaryRepos,
	}
}

func secondaryTestIsolateEnv() {
	ginkgo.GinkgoT().Setenv("WERF_BUILDAH_MODE", "")
	for _, keyValue := range os.Environ() {
		key, value, _ := strings.Cut(keyValue, "=")
		if !strings.HasPrefix(key, "WERF_SECONDARY_REPO_") {
			continue
		}
		gomega.Expect(os.Unsetenv(key)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(os.Setenv(key, value)).To(gomega.Succeed())
		})
	}
}

func secondaryTestStorageAddresses(storages []storage.StagesStorage) []string {
	addresses := make([]string, 0, len(storages))
	for _, s := range storages {
		addresses = append(addresses, s.Address())
	}
	return addresses
}

func synchronizationTestStorage(ctx context.Context) *storage.RepoStagesStorage {
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)
	address := strings.TrimPrefix(server.URL, "http://") + "/test/repo"
	client, err := docker_registry.NewDockerRegistry(ctx, address, docker_registry.DefaultImplementationName, docker_registry.DockerRegistryOptions{InsecureRegistry: true})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return storage.NewRepoStagesStorage(&storage.NewRepoStagesStorageOptions{RepoAddress: address, DockerRegistry: client})
}

type synchronizationDNSFailureTransport struct{ next http.RoundTripper }

var _ http.RoundTripper = (*synchronizationDNSFailureTransport)(nil)

func (transport *synchronizationDNSFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Hostname() == "synchronization.werf.io" {
		return nil, &net.DNSError{Err: "no such host", Name: request.URL.Hostname(), IsNotFound: true}
	}
	return transport.next.RoundTrip(request)
}
