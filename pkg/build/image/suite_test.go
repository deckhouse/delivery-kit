package image

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestImageSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Build Image Suite")
}
