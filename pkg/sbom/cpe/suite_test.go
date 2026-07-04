package cpe

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSbomCpe(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sbom Cpe Suite")
}
