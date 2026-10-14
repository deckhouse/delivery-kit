package build

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/werf"
)

func TestBuild(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Build Suite")
}

// Every spec gets its own werf tmp dir: the global one set by a previous
// spec points at a TempDir that Ginkgo has already removed.
var _ = BeforeEach(func() {
	Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
})
