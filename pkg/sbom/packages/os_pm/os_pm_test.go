package os_pm

import (
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const testContainerFactoryVersion = "v1.0.0-test"

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

	It("should return an empty map for an empty JSON object", func() {
		pkgs, err := ParsePmInstalledJSON([]byte(`{}`))
		Expect(err).To(Succeed())
		Expect(pkgs).To(BeEmpty())
	})
})

var _ = Describe("ConvertToCycloneDX", func() {
	It("generates valid CycloneDX BOM with correct component count", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs, testContainerFactoryVersion)
		Expect(bom).ToNot(BeNil())
		Expect(*bom.Components).To(HaveLen(6))
	})

	It("should set component name and version from package info", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs, testContainerFactoryVersion)
		Expect(*bom.Components).To(ContainElement(HaveField("Name", "curl")))
		Expect(*bom.Components).To(ContainElement(HaveField("Version", "8.12.1")))
	})

	DescribeTable("component type",
		func(name string) {
			comp := goldenComponent(loadGoldenPmBOM(), name)
			Expect(comp.Type).To(Equal(cdx.ComponentTypeLibrary))
		},
		Entry("curl", "curl"),
		Entry("brotli", "brotli"),
		Entry("jq", "jq"),
		Entry("libidn2", "libidn2"),
		Entry("libpsl", "libpsl"),
		Entry("libunistring", "libunistring"),
	)

	It("should set licenses from package info", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs, testContainerFactoryVersion)

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

	DescribeTable("PURL is set for every component",
		func(name string) {
			comp := goldenComponent(loadGoldenPmBOM(), name)
			Expect(comp.PackageURL).ToNot(BeEmpty(), "component %s should have PURL", comp.Name)
		},
		Entry("curl", "curl"),
		Entry("brotli", "brotli"),
		Entry("jq", "jq"),
		Entry("libidn2", "libidn2"),
		Entry("libpsl", "libpsl"),
		Entry("libunistring", "libunistring"),
	)

	It("should return nil for empty input", func() {
		bom := ConvertToCycloneDX(map[string]PmPackageInfo{}, testContainerFactoryVersion)
		Expect(bom).To(BeNil())
	})

	It("should handle packages with SPDX license IDs correctly", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs, testContainerFactoryVersion)

		for _, comp := range *bom.Components {
			if comp.Name == "libunistring" {
				Expect(comp.Licenses).ToNot(BeNil())
				Expect((*comp.Licenses)[0].License.ID).To(Equal("LGPL-3.0-or-later"))
			}
		}
	})
})

var _ = Describe("ParsePmInstalledJSON golden fixture (AI)", func() {
	It("parses the real-world pm info --installed --json contract", func() {
		data, err := os.ReadFile("testdata/pm_info_installed.json")
		Expect(err).To(Succeed())

		pkgs, err := ParsePmInstalledJSON(data)
		Expect(err).To(Succeed())
		Expect(pkgs).ToNot(BeEmpty())

		curl, ok := pkgs["curl"]
		Expect(ok).To(BeTrue())
		Expect(curl.Name).To(Equal("curl"))
		Expect(curl.Version).ToNot(BeEmpty())
		Expect(curl.Arch).ToNot(BeEmpty())
		Expect(curl.Type).ToNot(BeEmpty())
		Expect(curl.License).ToNot(BeEmpty())
		Expect(curl.OriginalRepo).To(HavePrefix("https://"))
		Expect(curl.Digest).To(HavePrefix("sha256:"))
		Expect(curl.Depends).To(ConsistOf("brotli", "libpsl"))
	})
})

var _ = Describe("ConvertToCycloneDX provenance and dependency graph (AI)", func() {
	It("maps the package digest into a CycloneDX SHA-256 hash", func() {
		curl := goldenComponent(loadGoldenPmBOM(), "curl")
		Expect(curl.Hashes).ToNot(BeNil())
		Expect(*curl.Hashes).To(HaveLen(1))

		h := (*curl.Hashes)[0]
		Expect(h.Algorithm).To(Equal(cdx.HashAlgoSHA256))
		Expect(h.Value).To(Equal("6f2108c511daa7c46ace9879c0d9bbef2573fb5fd88bee5fad745d96ceda081d"))
	})

	It("records architecture, type and repo as component properties", func() {
		curl := goldenComponent(loadGoldenPmBOM(), "curl")
		Expect(curl.Properties).ToNot(BeNil())
		Expect(*curl.Properties).To(ContainElement(cdx.Property{Name: "werf:pm:arch", Value: "linux/amd64"}))
		Expect(*curl.Properties).To(ContainElement(cdx.Property{Name: "werf:pm:type", Value: "runtime"}))
		Expect(*curl.Properties).To(ContainElement(cdx.Property{Name: "werf:pm:repo", Value: "curl/curl"}))
	})

	It("records cataloger name and artifact type for every pm component", func() {
		bom := loadGoldenPmBOM()
		for _, comp := range *bom.Components {
			Expect(comp.Properties).ToNot(BeNil(), "component %s must have properties", comp.Name)
			Expect(*comp.Properties).To(ContainElement(cdx.Property{Name: "werf:package:foundBy", Value: "pm-cataloger"}), "component %s must declare foundBy", comp.Name)
			Expect(*comp.Properties).To(ContainElement(cdx.Property{Name: "werf:package:type", Value: "binary"}), "component %s must declare artifact type=binary", comp.Name)
		}
	})

	It("sets the component description from package info", func() {
		curl := goldenComponent(loadGoldenPmBOM(), "curl")
		Expect(curl.Description).To(Equal("URL retrival utility and library"))
	})

	It("encodes the container-factory version as a purl qualifier", func() {
		curl := goldenComponent(loadGoldenPmBOM(), "curl")
		Expect(curl.PackageURL).To(HavePrefix("pkg:generic/curl@8.12.1?"))
		Expect(curl.PackageURL).To(ContainSubstring("containerfactoryversion=" + testContainerFactoryVersion))
		Expect(curl.PackageURL).ToNot(ContainSubstring("repository_url="))
	})

	It("emits a dependency graph from the package depends field", func() {
		bom := loadGoldenPmBOM()
		Expect(bom.Dependencies).ToNot(BeNil())

		curlPurl := goldenComponent(bom, "curl").BOMRef
		brotliPurl := goldenComponent(bom, "brotli").BOMRef
		libpslPurl := goldenComponent(bom, "libpsl").BOMRef

		var curlDeps *[]string
		for _, dep := range *bom.Dependencies {
			if dep.Ref == curlPurl {
				curlDeps = dep.Dependencies
			}
		}
		Expect(curlDeps).ToNot(BeNil(), "curl must have a dependency entry")
		Expect(*curlDeps).To(ConsistOf(brotliPurl, libpslPurl))
	})

	It("omits dependency entries for packages without dependencies", func() {
		bom := loadGoldenPmBOM()
		brotliPurl := goldenComponent(bom, "brotli").BOMRef

		for _, dep := range *bom.Dependencies {
			Expect(dep.Ref).ToNot(Equal(brotliPurl), "brotli has no depends and must not be a dependency source")
		}
	})
})

var _ = Describe("ConvertToCycloneDX bom-ref (AI)", func() {
	DescribeTable("bom-ref matches purl",
		func(name string) {
			comp := goldenComponent(loadGoldenPmBOM(), name)
			Expect(comp.BOMRef).ToNot(BeEmpty(), "component %s should have bom-ref", comp.Name)
			Expect(comp.BOMRef).To(Equal(comp.PackageURL), "component %s bom-ref should equal purl", comp.Name)
		},
		Entry("curl", "curl"),
		Entry("brotli", "brotli"),
		Entry("jq", "jq"),
		Entry("libidn2", "libidn2"),
		Entry("libpsl", "libpsl"),
		Entry("libunistring", "libunistring"),
	)

	It("produces unique bom-refs across components", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs, testContainerFactoryVersion)
		Expect(bom).ToNot(BeNil())

		seen := map[string]struct{}{}
		for _, comp := range *bom.Components {
			_, dup := seen[comp.BOMRef]
			Expect(dup).To(BeFalse(), "bom-ref %s must be unique", comp.BOMRef)
			seen[comp.BOMRef] = struct{}{}
		}
	})
})

var _ = Describe("ConvertToCycloneDX CPE integration", func() {
	DescribeTable("primary component.cpe uses the highest-confidence vendor",
		func(name, expectedCPE string) {
			comp := goldenComponent(loadGoldenPmBOM(), name)
			Expect(comp.CPE).To(Equal(expectedCPE), "component %s must expose the curated/URL-derived CPE as primary", name)
			Expect(comp.Evidence).ToNot(BeNil(), "component %s must carry CPE evidence", name)
			Expect(comp.Evidence.Identity).ToNot(BeNil(), "component %s must expose evidence.identity entries", name)
		},
		Entry("curl uses haxx curated override", "curl", "cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*"),
		Entry("brotli uses google URL vendor", "brotli", "cpe:2.3:a:google:brotli:1.1.0:*:*:*:*:*:*:*"),
		Entry("jq uses jqlang homepage mapping", "jq", "cpe:2.3:a:jqlang:jq:1.8.1:*:*:*:*:*:*:*"),
		Entry("libunistring uses gnu URL vendor", "libunistring", "cpe:2.3:a:gnu:libunistring:1.4.1:*:*:*:*:*:*:*"),
	)
})

func loadGoldenPmBOM() *cdx.BOM {
	data, err := os.ReadFile("testdata/pm_info_installed.json")
	Expect(err).To(Succeed())

	pkgs, err := ParsePmInstalledJSON(data)
	Expect(err).To(Succeed())

	bom := ConvertToCycloneDX(pkgs, testContainerFactoryVersion)
	Expect(bom).ToNot(BeNil())

	return bom
}

func goldenComponent(bom *cdx.BOM, name string) cdx.Component {
	for _, comp := range *bom.Components {
		if comp.Name == name {
			return comp
		}
	}
	Fail("component not found: " + name)

	return cdx.Component{}
}
