package signing_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSigning(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Signing Suite")
}
