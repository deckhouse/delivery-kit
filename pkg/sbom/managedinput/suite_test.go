package managedinput

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestManagedInput(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Managed Input Suite")
}
