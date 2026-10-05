package declared

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSbomDeclared(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sbom Declared Suite")
}
