package build

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
)

var _ = Describe("SbomStep SBOM missing error", func() {
	It("keeps the attach guidance, stays dependency-kind neutral, and adds the legacy multi-platform hint", func() {
		cause := errors.New("pull SBOM for \"base\": artifact not found")
		err := sbomMissingError(&image.Info{Name: "registry.example.com/base:tag"}, cause)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("registry.example.com/base:tag"))
		Expect(err.Error()).To(ContainSubstring("must have an SBOM artifact attached"))
		Expect(err.Error()).To(ContainSubstring("rebuild the image with a newer werf version"))
		Expect(err.Error()).To(ContainSubstring("legacy platform-ambiguous format"))
		Expect(err.Error()).NotTo(ContainSubstring("base image"), "GetImageBOM serves both base and import dependencies; the message must not claim the image is a base")
		Expect(errors.Is(err, cause)).To(BeTrue())
	})
})
