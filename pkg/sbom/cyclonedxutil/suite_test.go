package cyclonedxutil

import (
	"fmt"
	"net/http"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCyclonedxUtil(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CyclonedxUtil Suite")
}

// The schema loader must resolve every $ref from the embedded schemas: werf runs
// where the network is unavailable, so a fetch here is a bug and not a slow path.
var _ = BeforeSuite(func() {
	http.DefaultTransport = networkBlockedTransport{}
})

type networkBlockedTransport struct{}

var _ http.RoundTripper = networkBlockedTransport{}

func (networkBlockedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network access is blocked in unit tests, attempted %s", req.URL)
}
