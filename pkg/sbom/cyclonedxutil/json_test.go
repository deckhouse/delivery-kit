package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const streebog256Content = "4559fe98d002ff12ab69dafaf495d49ab7bfe14fd4408bf733dd99b3056c65bf"

var _ = Describe("ToJSON", func() {
	newBOM := func(comp cdx.Component) *cdx.BOM {
		return &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Version:     1,
			Components:  &[]cdx.Component{comp},
		}
	}

	It("keeps the STREEBOG digest of a source distribution", func() {
		data, err := ToJSON(newBOM(cdx.Component{
			Type: cdx.ComponentTypeLibrary,
			Name: "commondir",
			ExternalReferences: &[]cdx.ExternalReference{{
				URL:    "https://registry.npmjs.org/commondir/-/commondir-1.0.1.tgz",
				Type:   cdx.ERTypeSourceDistribution,
				Hashes: &[]cdx.Hash{{Algorithm: "STREEBOG-256", Value: streebog256Content}},
			}},
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring(`"alg":"STREEBOG-256"`))
		Expect(ValidateCycloneDX16Schema(data)).To(Succeed())
	})

	It("reports a STREEBOG digest the encoder would drop from a component", func() {
		_, err := ToJSON(newBOM(cdx.Component{
			Type:   cdx.ComponentTypeLibrary,
			Name:   "commondir",
			Hashes: &[]cdx.Hash{{Algorithm: "STREEBOG-256", Value: streebog256Content}},
		}))

		Expect(err).To(MatchError(ContainSubstring(`component "commondir" carries a STREEBOG-256 hash, which the CycloneDX 1.6 encoder drops`)))
	})

	It("reports a STREEBOG digest on a nested component", func() {
		_, err := ToJSON(newBOM(cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: "app",
			Components: &[]cdx.Component{{
				Type:   cdx.ComponentTypeLibrary,
				Name:   "nested",
				Hashes: &[]cdx.Hash{{Algorithm: "STREEBOG-512", Value: streebog256Content}},
			}},
		}))

		Expect(err).To(MatchError(ContainSubstring(`component "nested" carries a STREEBOG-512 hash`)))
	})

	It("keeps the hashes the spec version knows", func() {
		data, err := ToJSON(newBOM(cdx.Component{
			Type:   cdx.ComponentTypeLibrary,
			Name:   "commondir",
			Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: streebog256Content}},
		}))

		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring(`"alg":"SHA-256"`))
	})
})
