package cpe

import (
	"encoding/json"
	"os"

	"github.com/facebookincubator/nvdtools/wfn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GenerateForPmPackage", func() {
	DescribeTable("selects the highest-confidence vendor as the primary CPE and covers known variations",
		func(input PackageInput, expectedPrimary string, expectedCPEs []string) {
			candidates := GenerateForPmPackage(input)
			Expect(candidates).ToNot(BeEmpty())

			got := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				got = append(got, candidate.String())
			}

			Expect(candidates[0].String()).To(Equal(expectedPrimary),
				"primary CPE must come from the highest-confidence vendor source; got order: %v", got)

			for _, expected := range expectedCPEs {
				Expect(got).To(ContainElement(expected))
			}
		},
		Entry("curl uses haxx curated override as primary",
			PackageInput{Name: "curl", Version: "8.12.1", OriginalRepo: "https://github.com/curl/curl", Repo: "curl/curl"},
			"cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*",
			[]string{
				"cpe:2.3:a:haxx:curl:8.12.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:curl:curl:8.12.1:*:*:*:*:*:*:*",
			},
		),
		Entry("brotli uses google URL vendor as primary",
			PackageInput{Name: "brotli", Version: "1.1.0", OriginalRepo: "https://github.com/google/brotli", Repo: "google/brotli"},
			"cpe:2.3:a:google:brotli:1.1.0:*:*:*:*:*:*:*",
			[]string{"cpe:2.3:a:google:brotli:1.1.0:*:*:*:*:*:*:*"},
		),
		Entry("bash uses gnu vendor from savannah URL as primary",
			PackageInput{Name: "bash", Version: "5.3", OriginalRepo: "https://cgit.git.savannah.gnu.org/cgit/bash.git/", Repo: "git/bash"},
			"cpe:2.3:a:gnu:bash:5.3:*:*:*:*:*:*:*",
			[]string{"cpe:2.3:a:gnu:bash:5.3:*:*:*:*:*:*:*"},
		),
		Entry("openssl uses openssl homepage mapping as primary",
			PackageInput{Name: "openssl", Version: "3.6.2", OriginalRepo: "https://www.openssl.org/", Repo: "openssl/openssl"},
			"cpe:2.3:a:openssl:openssl:3.6.2:*:*:*:*:*:*:*",
			[]string{"cpe:2.3:a:openssl:openssl:3.6.2:*:*:*:*:*:*:*"},
		),
		Entry("jq uses jqlang homepage mapping as primary",
			PackageInput{Name: "jq", Version: "1.8.1", OriginalRepo: "https://jqlang.github.io/jq/", Repo: "jqlang/jq"},
			"cpe:2.3:a:jqlang:jq:1.8.1:*:*:*:*:*:*:*",
			[]string{"cpe:2.3:a:jqlang:jq:1.8.1:*:*:*:*:*:*:*"},
		),
		Entry("empty originalRepo prefers repo owner over name-derived vendor",
			PackageInput{Name: "lua-protobuf", Version: "0.5.1", OriginalRepo: "", Repo: "starwing/lua-protobuf"},
			"cpe:2.3:a:starwing:lua-protobuf:0.5.1:*:*:*:*:*:*:*",
			[]string{
				"cpe:2.3:a:starwing:lua-protobuf:0.5.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:lua-protobuf:lua-protobuf:0.5.1:*:*:*:*:*:*:*",
			},
		),
		Entry("util-linux prefers kernel curated override as primary",
			PackageInput{Name: "util-linux", Version: "2.40", Repo: "util-linux/util-linux"},
			"cpe:2.3:a:kernel:util-linux:2.40:*:*:*:*:*:*:*",
			[]string{
				"cpe:2.3:a:util-linux:util-linux:2.40:*:*:*:*:*:*:*",
				"cpe:2.3:a:util_linux:util_linux:2.40:*:*:*:*:*:*:*",
				"cpe:2.3:a:kernel:util-linux:2.40:*:*:*:*:*:*:*",
				"cpe:2.3:a:util:util-linux:2.40:*:*:*:*:*:*:*",
			},
		),
		Entry("wpa_supplicant prefers w1.fi URL vendor as primary",
			PackageInput{Name: "wpa_supplicant", Version: "2.11", OriginalRepo: "https://w1.fi/"},
			"cpe:2.3:a:w1.fi:wpa-supplicant:2.11:*:*:*:*:*:*:*",
			[]string{
				"cpe:2.3:a:wpa_supplicant:wpa_supplicant:2.11:*:*:*:*:*:*:*",
				"cpe:2.3:a:wpa-supplicant:wpa-supplicant:2.11:*:*:*:*:*:*:*",
				"cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
			},
		),
	)

	It("returns only the known vendor when a package name maps to one", func() {
		// httpd maps to the known vendor "apache"; the known-vendor preference
		// suppresses noisier guesses and keeps only apache-vendored CPEs.
		candidates := GenerateForPmPackage(PackageInput{Name: "httpd", Version: "2.4.62", Repo: "apache/httpd"})
		Expect(candidates).ToNot(BeEmpty())

		for _, candidate := range candidates {
			attrs, err := wfn.UnbindFmtString(candidate.String())
			Expect(err).To(Succeed())
			Expect(attrs.Vendor).To(Equal("apache"),
				"known vendor preference must keep only apache: %s", candidate.String())
		}
	})

	It("produces at least one well-formed CPE for every package in the pm golden fixture", func() {
		data, err := os.ReadFile("../packages/os_pm/testdata/pm_info_installed.json")
		Expect(err).To(Succeed())

		var lockFile struct {
			Packages map[string]struct {
				Name         string `json:"name"`
				Version      string `json:"version"`
				OriginalRepo string `json:"originalRepo"`
				Repo         string `json:"repo"`
			} `json:"packages"`
		}
		Expect(json.Unmarshal(data, &lockFile)).To(Succeed())
		pkgs := lockFile.Packages

		resolved := 0
		for _, pkg := range pkgs {
			candidates := GenerateForPmPackage(PackageInput{
				Name:         pkg.Name,
				Version:      pkg.Version,
				OriginalRepo: pkg.OriginalRepo,
				Repo:         pkg.Repo,
			})
			if len(candidates) > 0 {
				resolved++
			}
			for _, candidate := range candidates {
				_, err := wfn.UnbindFmtString(candidate.String())
				Expect(err).To(Succeed())
			}
		}

		Expect(resolved).To(Equal(len(pkgs)),
			"all packages in golden pm fixture should get at least one CPE candidate")
	})
})
