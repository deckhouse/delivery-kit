package ls

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
)

func TestAttestLs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Attest Ls Suite")
}

var _ = Describe("infosToRows", func() {
	It("renders one row per attestation with the platform column", func() {
		infos := []attestation.AttestationInfo{
			{PredicateType: "https://cyclonedx.org/bom", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Signed: true},
			{PredicateType: "", Digest: "sha256:bb", Signed: false},
		}

		rows := infosToRows("linux/amd64", infos)

		Expect(rows).To(HaveLen(2))
		Expect(rows[0].platform).To(Equal("linux/amd64"))
		Expect(rows[0].predicateType).To(Equal("https://cyclonedx.org/bom"))
		Expect(rows[0].digest).To(Equal("sha256:aaaaaaaaaaaa..."))
		Expect(rows[0].signed).To(Equal("yes"))
		Expect(rows[1].predicateType).To(Equal("(unknown)"))
		Expect(rows[1].digest).To(Equal("sha256:bb"))
		Expect(rows[1].signed).To(Equal("no"))
	})

	It("renders a dash for a non-index (platformless) entry", func() {
		rows := infosToRows("", []attestation.AttestationInfo{{Digest: "sha256:cc"}})

		Expect(rows).To(HaveLen(1))
		Expect(rows[0].platform).To(Equal("-"))
	})

	It("produces distinct platform values for distinct index entries", func() {
		amd64Rows := infosToRows("linux/amd64", []attestation.AttestationInfo{{Digest: "sha256:aa"}})
		arm64Rows := infosToRows("linux/arm64", []attestation.AttestationInfo{{Digest: "sha256:bb"}})

		Expect(amd64Rows[0].platform).NotTo(Equal(arm64Rows[0].platform))
	})
})
