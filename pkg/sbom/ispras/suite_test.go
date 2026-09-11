package ispras

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestIspras(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ispras Suite")
}
