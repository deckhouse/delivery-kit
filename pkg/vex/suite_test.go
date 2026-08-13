package vex_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestVex(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VEX Suite")
}
