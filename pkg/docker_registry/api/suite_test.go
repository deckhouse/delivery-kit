package api

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMutate(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Docker Registry API Suite")
}
