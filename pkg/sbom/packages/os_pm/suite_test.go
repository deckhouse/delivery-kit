package os_pm

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSbomPackagesOsPm(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sbom Packages OsPm Suite")
}
