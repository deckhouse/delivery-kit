package convergefailure

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConvergeFailure(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SBOM converge failure suite")
}
