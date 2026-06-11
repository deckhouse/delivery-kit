package os_pm

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var examplePmInstalledJSON = []byte(`{
  "brotli": {
    "name": "brotli",
    "arch": ["linux/amd64"],
    "default": true,
    "description": "Generic lossless compressor",
    "license": "MIT",
    "originalRepo": "https://github.com/google/brotli",
    "repo": "google/brotli",
    "type": "runtime",
    "version": "1.1.0",
    "digest": "sha256:82dcd7127798a506c1ab00993dffaf4ddd2bf576fba97a5d1cc45b931bcd2a0f"
  },
  "curl": {
    "name": "curl",
    "arch": ["linux/amd64"],
    "default": true,
    "depends": ["brotli", "libpsl"],
    "description": "URL retrival utility and library",
    "license": "curl",
    "originalRepo": "https://github.com/curl/curl",
    "repo": "curl/curl",
    "type": "runtime",
    "version": "8.12.1",
    "digest": "sha256:6f2108c511daa7c46ace9879c0d9bbef2573fb5fd88bee5fad745d96ceda081d"
  },
  "jq": {
    "name": "jq",
    "arch": ["linux/amd64"],
    "default": true,
    "description": "A lightweight and flexible command-line JSON processor",
    "license": "MIT",
    "originalRepo": "https://jqlang.github.io/jq/",
    "repo": "jqlang/jq",
    "type": "runtime",
    "version": "1.8.1",
    "digest": "sha256:4b36dcf53c35b50e0afbc445232713aff15f788a61b832cd720bf9e88fc9fba8"
  },
  "libidn2": {
    "name": "libidn2",
    "arch": ["linux/amd64"],
    "default": true,
    "depends": ["libunistring"],
    "description": "Encode/Decode library for internationalized domain names",
    "license": "BSD-3-Clause",
    "originalRepo": "https://gitlab.com/libidn/libidn2",
    "repo": "libidn/libidn2",
    "type": "runtime",
    "version": "2.3.8",
    "digest": "sha256:71efcb507c12a77b262038c18043695ee65d27f79f2d6dba052bb0a9e59589e5"
  },
  "libpsl": {
    "name": "libpsl",
    "arch": ["linux/amd64"],
    "default": true,
    "depends": ["libidn2", "libunistring"],
    "description": "C library for the Publix Suffix List.",
    "license": "MIT",
    "originalRepo": "https://github.com/rockdaboot/libpsl",
    "repo": "rockdaboot/libpsl",
    "type": "runtime",
    "version": "0.21.5",
    "digest": "sha256:9cec4175f81c57c445b8f4904dfecc3c98e35416e8bbcabd3206537b7055687e"
  },
  "libunistring": {
    "name": "libunistring",
    "arch": ["linux/amd64"],
    "default": true,
    "description": "Library for manipulating Unicode strings and C strings.",
    "license": "LGPL-3.0-or-later",
    "originalRepo": "https://git.savannah.gnu.org/git/libunistring.git",
    "repo": "git/libunistring",
    "type": "runtime",
    "version": "1.4.1",
    "digest": "sha256:2d2a7d27c1c23f4b169c58bcf0104509a28c3bd73d8293969f067fa4820fb79b"
  }
}`)

var _ = Describe("ParsePmInstalledJSON", func() {
	It("should parse valid pm info JSON", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())
		Expect(pkgs).To(HaveLen(6))
	})

	It("should parse curl package fields correctly", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		curl, ok := pkgs["curl"]
		Expect(ok).To(BeTrue())
		Expect(curl.Name).To(Equal("curl"))
		Expect(curl.Version).To(Equal("8.12.1"))
		Expect(curl.License).To(Equal("curl"))
		Expect(curl.Digest).To(Equal("sha256:6f2108c511daa7c46ace9879c0d9bbef2573fb5fd88bee5fad745d96ceda081d"))
		Expect(curl.Depends).To(ConsistOf("brotli", "libpsl"))
	})

	It("should parse jq package fields correctly", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		jq, ok := pkgs["jq"]
		Expect(ok).To(BeTrue())
		Expect(jq.Name).To(Equal("jq"))
		Expect(jq.Version).To(Equal("1.8.1"))
		Expect(jq.License).To(Equal("MIT"))
		Expect(jq.Digest).To(Equal("sha256:4b36dcf53c35b50e0afbc445232713aff15f788a61b832cd720bf9e88fc9fba8"))
		Expect(jq.Depends).To(BeEmpty())
	})

	It("should parse transitive dependency fields", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		libpsl, ok := pkgs["libpsl"]
		Expect(ok).To(BeTrue())
		Expect(libpsl.Version).To(Equal("0.21.5"))
		Expect(libpsl.License).To(Equal("MIT"))
		Expect(libpsl.Depends).To(ConsistOf("libidn2", "libunistring"))
	})

	It("should parse package without dependencies", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		brotli, ok := pkgs["brotli"]
		Expect(ok).To(BeTrue())
		Expect(brotli.Version).To(Equal("1.1.0"))
		Expect(brotli.License).To(Equal("MIT"))
		Expect(brotli.Depends).To(BeEmpty())
	})

	It("should return error for invalid JSON", func() {
		_, err := ParsePmInstalledJSON([]byte(`{invalid}`))
		Expect(err).To(HaveOccurred())
	})

	It("should return error for empty JSON", func() {
		_, err := ParsePmInstalledJSON([]byte(`{}`))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("ConvertToCycloneDX", func() {
	It("should generate valid CycloneDX BOM with correct component count", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)
		Expect(bom).ToNot(BeNil())
		Expect(*bom.Components).To(HaveLen(6))
	})

	It("should set component name and version from package info", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)
		Expect(*bom.Components).To(ContainElement(HaveField("Name", "curl")))
		Expect(*bom.Components).To(ContainElement(HaveField("Version", "8.12.1")))
	})

	It("should set component type to Library", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)
		for _, comp := range *bom.Components {
			Expect(comp.Type).To(Equal(cdx.ComponentTypeLibrary))
		}
	})

	It("should set licenses from package info", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)

		var mitComponents int
		for _, comp := range *bom.Components {
			if comp.Licenses != nil {
				for _, l := range *comp.Licenses {
					if l.License != nil && l.License.ID == "MIT" {
						mitComponents++
					}
				}
			}
		}
		Expect(mitComponents).To(BeNumerically(">=", 1))
	})

	It("should set PURL for each component", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)
		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).ToNot(BeEmpty(), "component %s should have PURL", comp.Name)
		}
	})

	It("should return nil for empty input", func() {
		bom := ConvertToCycloneDX(map[string]PmPackageInfo{})
		Expect(bom).To(BeNil())
	})

	It("should handle packages with SPDX license IDs correctly", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)

		for _, comp := range *bom.Components {
			if comp.Name == "libunistring" {
				Expect(comp.Licenses).ToNot(BeNil())
				Expect((*comp.Licenses)[0].License.ID).To(Equal("LGPL-3.0-or-later"))
			}
		}
	})
})
