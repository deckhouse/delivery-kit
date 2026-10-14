package shippedscope

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestShippedScope(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shipped Scope Suite")
}
