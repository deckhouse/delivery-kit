package metadata

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMetadataSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OS PM Metadata Suite")
}
