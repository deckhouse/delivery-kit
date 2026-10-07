package cyclonedxutil

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

var _ = Describe("CycloneDX Schema Validation", func() {
	Describe("ValidateCycloneDX16Schema", func() {
		DescribeTable("validates JSON against schema",
			func(jsonStr string, matcher types.GomegaMatcher) {
				err := ValidateCycloneDX16Schema([]byte(jsonStr))
				Expect(err).To(matcher)
			},

			Entry("empty JSON",
				`   `,
				HaveOccurred()),

			Entry("invalid JSON syntax",
				`{"bomFormat":`,
				HaveOccurred()),

			Entry("valid minimal BOM",
				`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`,
				Succeed()),

			Entry("invalid bomFormat",
				`{"bomFormat":"SPDX","specVersion":"1.6","version":1}`,
				MatchError(ContainSubstring("bomFormat"))),

			Entry("invalid specVersion",
				`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`,
				MatchError(ContainSubstring("specVersion"))),

			Entry("missing specVersion (zero value is not 1.6)",
				`{"bomFormat":"CycloneDX","version":1}`,
				MatchError(ContainSubstring("specVersion"))),

			Entry("version less than 1",
				`{"bomFormat":"CycloneDX","specVersion":"1.6","version":0}`,
				MatchError(ContainSubstring("version"))),

			Entry("invalid serialNumber",
				`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"not-a-uuid"}`,
				MatchError(ContainSubstring("serialNumber"))),

			Entry("invalid license format (flat)",
				`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.6",
					"version": 1,
					"components": [
						{
							"type": "library",
							"name": "test",
							"licenses": [
								{ "id": "MIT" }
							]
						}
					]
				}`,
				MatchError(ContainSubstring("Must validate one and only one schema"))),

			Entry("SPDX expression in license.id",
				`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.6",
					"version": 1,
					"components": [
						{
							"type": "library",
							"name": "rust",
							"licenses": [
								{ "license": { "id": "Apache-2.0 OR MIT" } }
							]
						}
					]
				}`,
				MatchError(ContainSubstring("components.0.licenses.0.license.id"))),

			Entry("SPDX id and expression in their own fields",
				`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.6",
					"version": 1,
					"components": [
						{
							"type": "library",
							"name": "curl",
							"licenses": [
								{ "license": { "id": "curl" } }
							]
						},
						{
							"type": "library",
							"name": "rust",
							"licenses": [
								{ "expression": "Apache-2.0 OR MIT" }
							]
						}
					]
				}`,
				Succeed()),

			Entry("STREEBOG digest on a source distribution",
				`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.6",
					"version": 1,
					"components": [
						{
							"type": "library",
							"name": "commondir",
							"externalReferences": [
								{
									"type": "source-distribution",
									"url": "https://registry.npmjs.org/commondir/-/commondir-1.0.1.tgz",
									"hashes": [
										{ "alg": "STREEBOG-256", "content": "4559fe98d002ff12ab69dafaf495d49ab7bfe14fd4408bf733dd99b3056c65bf" }
									]
								}
							]
						}
					]
				}`,
				Succeed()),

			Entry("hash algorithm outside the extended enum",
				`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.6",
					"version": 1,
					"components": [
						{
							"type": "library",
							"name": "commondir",
							"externalReferences": [
								{
									"type": "source-distribution",
									"url": "https://registry.npmjs.org/commondir/-/commondir-1.0.1.tgz",
									"hashes": [
										{ "alg": "Streebog-256", "content": "4559fe98d002ff12ab69dafaf495d49ab7bfe14fd4408bf733dd99b3056c65bf" }
									]
								}
							]
						}
					]
				}`,
				MatchError(ContainSubstring("alg"))),
		)
	})

	Describe("SPDXLicenseIDKnown", func() {
		DescribeTable("reports membership in the embedded SPDX license list",
			func(id string, expected bool) {
				known, err := SPDXLicenseIDKnown(id)
				Expect(err).NotTo(HaveOccurred())
				Expect(known).To(Equal(expected))
			},
			Entry("a license id", "MIT", true),
			Entry("a deprecated license id", "GPL-2.0+", true),
			Entry("an exception id", "LLVM-exception", true),
			Entry("an expression is not an id", "MIT OR Apache-2.0", false),
			Entry("free text", "GPLv3", false),
			Entry("the list is case-sensitive", "mit", false),
		)
	})

	Describe("HashAlgorithmAllowed", func() {
		DescribeTable("reports membership in the embedded schema's hash-alg enum",
			func(alg string, expected bool) {
				allowed, err := HashAlgorithmAllowed(alg)
				Expect(err).NotTo(HaveOccurred())
				Expect(allowed).To(Equal(expected))
			},
			Entry("SHA-256 is accepted", "SHA-256", true),
			Entry("the STREEBOG extension is accepted", "STREEBOG-256", true),
			Entry("STREEBOG-512 is accepted", "STREEBOG-512", true),
			Entry("an unknown algorithm is not", "MD6", false),
			Entry("the enum is case-sensitive", "sha-256", false),
		)
	})
})
