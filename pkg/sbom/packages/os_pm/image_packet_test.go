package os_pm

import (
	"context"
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Labels of the prepared glibc source image built by the source image tool, the
// shape this adapter has to read.
func exampleSourceImageLabels() map[string]string {
	return map[string]string{
		"pkg.name":         "glibc-source",
		"pkg.version":      "2.43",
		"pkg.type":         "source",
		"pkg.arch":         "linux/amd64",
		"pkg.default":      "false",
		"pkg.repo":         "glibc",
		"pkg.originalRepo": "https://sourceware.org/git/glibc.git",
		"pkg.license":      "LGPL-2.1-or-later",
		"pkg.srcLanguages": "C,Assembly",
		"pkg.description":  "Prepared glibc sources and CSU generated headers",
	}
}

const (
	exampleSourceImageDigest = "sha256:bbb27569a9094b9cd32d7773505fb6c02fcbbcfb2ab4f80517b97489f49f84dd"
	exampleOtherImageDigest  = "sha256:fe86119ef9718c62fe2c643373e54f8e7f1047b1e6da468befa19fb95156f390"
)

var _ = Describe("PacketJSONFromImageLabels", func() {
	It("should build the packet JSON of a prepared source image", func() {
		data, err := PacketJSONFromImageLabels(context.Background(), exampleSourceImageLabels(), exampleSourceImageDigest)
		Expect(err).To(Succeed())
		Expect(string(data)).To(Equal(`{` +
			`"arch":["linux/amd64"],` +
			`"default":false,` +
			`"description":"Prepared glibc sources and CSU generated headers",` +
			`"digest":"` + exampleSourceImageDigest + `",` +
			`"license":"LGPL-2.1-or-later",` +
			`"name":"glibc-source",` +
			`"originalRepo":"https://sourceware.org/git/glibc.git",` +
			`"repo":"glibc",` +
			`"srcLanguages":["C","Assembly"],` +
			`"type":"source",` +
			`"version":"2.43"` +
			`}`))
	})

	It("should split every known list field by comma", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.arch"] = "linux/amd64,linux/arm64"
		labels["pkg.depends"] = "libgcc,libstdc++"

		data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(Succeed())
		Expect(string(data)).To(ContainSubstring(`"arch":["linux/amd64","linux/arm64"]`))
		Expect(string(data)).To(ContainSubstring(`"depends":["libgcc","libstdc++"]`))
		Expect(string(data)).To(ContainSubstring(`"srcLanguages":["C","Assembly"]`))
	})

	It("should accept any non-empty package type", func() {
		for _, packageType := range []string{"runtime", "devel", "source"} {
			labels := exampleSourceImageLabels()
			labels["pkg.type"] = packageType

			data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
			Expect(err).To(Succeed())
			Expect(string(data)).To(ContainSubstring(fmt.Sprintf(`"type":%q`, packageType)))
		}
	})

	It("should keep unknown pkg fields as the exact strings they are", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.aliasOf"] = "glibc"
		labels["pkg.packedSize"] = "123456789012345678901234567890"
		labels["pkg.buildNumber"] = "007"
		labels["pkg.notes"] = `<b>sources &amp; headers</b>`

		data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(Succeed())

		var decoded map[string]json.RawMessage
		Expect(json.Unmarshal(data, &decoded)).To(Succeed())
		Expect(string(decoded["aliasOf"])).To(Equal(`"glibc"`))
		Expect(string(decoded["packedSize"])).To(Equal(`"123456789012345678901234567890"`))
		Expect(string(decoded["buildNumber"])).To(Equal(`"007"`))
		Expect(string(decoded["notes"])).To(Equal(`"\u003cb\u003esources \u0026amp; headers\u003c/b\u003e"`))

		var notes string
		Expect(json.Unmarshal(decoded["notes"], &notes)).To(Succeed())
		Expect(notes).To(Equal(`<b>sources &amp; headers</b>`))
	})

	It("should keep unknown pkg fields whatever their suffix looks like", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.vendor-key"] = "deckhouse"
		labels["pkg.build.host.id"] = "runner-7"
		labels["pkg.9lives"] = "cat"
		labels["pkg.trailing."] = "dot"
		labels["pkg.src languages"] = "C"

		data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(Succeed())

		var decoded map[string]json.RawMessage
		Expect(json.Unmarshal(data, &decoded)).To(Succeed())
		Expect(string(decoded["vendor-key"])).To(Equal(`"deckhouse"`))
		Expect(string(decoded["build.host.id"])).To(Equal(`"runner-7"`))
		Expect(string(decoded["9lives"])).To(Equal(`"cat"`))
		Expect(string(decoded["trailing."])).To(Equal(`"dot"`))
		Expect(string(decoded["src languages"])).To(Equal(`"C"`))
	})

	It("should ignore labels outside the pkg namespace", func() {
		labels := exampleSourceImageLabels()
		labels["werf.io/version"] = "v3.0.0"
		labels["werf.io/sbom-build-context-v1"] = `{"version":1}`
		labels["org.opencontainers.image.source"] = "https://example.com/private"
		labels["pkgfoo"] = "not a package label"

		data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(Succeed())

		var decoded map[string]json.RawMessage
		Expect(json.Unmarshal(data, &decoded)).To(Succeed())
		Expect(decoded).To(HaveLen(11))
		Expect(string(data)).NotTo(ContainSubstring("werf.io"))
		Expect(string(data)).NotTo(ContainSubstring("opencontainers"))
		Expect(string(data)).NotTo(ContainSubstring("not a package label"))
	})

	It("should use the resolved image digest, not a digest guessed elsewhere", func() {
		labels := exampleSourceImageLabels()

		data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleOtherImageDigest)
		Expect(err).To(Succeed())
		Expect(string(data)).To(ContainSubstring(`"digest":"` + exampleOtherImageDigest + `"`))
	})

	It("should not coalesce the same package name and version built into different images", func() {
		first, err := PacketJSONFromImageLabels(context.Background(), exampleSourceImageLabels(), exampleSourceImageDigest)
		Expect(err).To(Succeed())
		second, err := PacketJSONFromImageLabels(context.Background(), exampleSourceImageLabels(), exampleOtherImageDigest)
		Expect(err).To(Succeed())
		Expect(string(first)).NotTo(Equal(string(second)))
	})

	It("should accept a digest label that repeats the resolved digest", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.digest"] = exampleSourceImageDigest

		data, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(Succeed())
		Expect(string(data)).To(ContainSubstring(`"digest":"` + exampleSourceImageDigest + `"`))
	})

	It("should reject a digest label that contradicts the resolved digest", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.digest"] = exampleOtherImageDigest

		_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(MatchError(ContainSubstring("contradicts image digest")))
		Expect(err).NotTo(MatchError(ErrNoImagePacketLabels))
	})

	It("should reject a digest that is not a canonical sha256 digest", func() {
		for _, digest := range []string{
			"",
			"bbb27569a9094b9cd32d7773505fb6c02fcbbcfb2ab4f80517b97489f49f84dd",
			"sha256:BBB27569A9094B9CD32D7773505FB6C02FCBBCFB2AB4F80517B97489F49F84DD",
			"sha256:bbb27569",
			"sha512:bbb27569a9094b9cd32d7773505fb6c02fcbbcfb2ab4f80517b97489f49f84dd",
			"glibc-source-2.43",
		} {
			_, err := PacketJSONFromImageLabels(context.Background(), exampleSourceImageLabels(), digest)
			Expect(err).To(MatchError(ContainSubstring("is not a canonical sha256 digest")), digest)
		}
	})

	It("should report no data when the image carries no pkg labels", func() {
		labels := map[string]string{"werf.io/version": "v3.0.0"}

		_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(MatchError(ErrNoImagePacketLabels))
	})

	It("should report no data when an identifying field is missing or empty", func() {
		for _, name := range []string{"name", "version", "type", "arch"} {
			missing := exampleSourceImageLabels()
			delete(missing, "pkg."+name)
			_, err := PacketJSONFromImageLabels(context.Background(), missing, exampleSourceImageDigest)
			Expect(err).To(MatchError(ErrNoImagePacketLabels), name)

			empty := exampleSourceImageLabels()
			empty["pkg."+name] = ""
			_, err = PacketJSONFromImageLabels(context.Background(), empty, exampleSourceImageDigest)
			Expect(err).To(MatchError(ErrNoImagePacketLabels), name)
		}
	})

	It("should reject a default label that is not canonical true or false", func() {
		for _, value := range []string{"True", "FALSE", "1", "yes", "0", " true"} {
			labels := exampleSourceImageLabels()
			labels["pkg.default"] = value

			_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
			Expect(err).To(MatchError(ContainSubstring("is not true or false")), value)
			Expect(err).NotTo(MatchError(ErrNoImagePacketLabels), value)
		}
	})

	It("should reject a list field with an empty item", func() {
		for _, label := range []string{"pkg.arch", "pkg.depends", "pkg.srcLanguages"} {
			for _, value := range []string{",", "C,,Assembly", "C,", ",C"} {
				labels := exampleSourceImageLabels()
				labels[label] = value

				_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
				Expect(err).To(MatchError(ContainSubstring("has an empty item")), label+"="+value)
			}
		}

		labels := exampleSourceImageLabels()
		labels["pkg.depends"] = ""
		_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(MatchError(ContainSubstring("has an empty item")))
	})

	It("should reject a pkg label with an empty field name", func() {
		labels := exampleSourceImageLabels()
		labels["pkg."] = "value"

		_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(MatchError(ContainSubstring("has an empty field name")))
		Expect(err).NotTo(MatchError(ErrNoImagePacketLabels))
	})

	It("should reject a pkg label key that is not valid UTF-8", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.desc\xffription"] = "value"

		_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(MatchError(ContainSubstring("is not valid UTF-8")))
	})

	It("should reject a label value that is not valid UTF-8", func() {
		labels := exampleSourceImageLabels()
		labels["pkg.description"] = "glibc \xff sources"

		_, err := PacketJSONFromImageLabels(context.Background(), labels, exampleSourceImageDigest)
		Expect(err).To(MatchError(ContainSubstring("is not valid UTF-8")))
	})

	It("should produce a packet the installed index parser understands", func() {
		data, err := PacketJSONFromImageLabels(context.Background(), exampleSourceImageLabels(), exampleSourceImageDigest)
		Expect(err).To(Succeed())

		pkgs, err := ParsePmInstalledJSON([]byte(`{"glibc-source":` + string(data) + `}`))
		Expect(err).To(Succeed())

		pkg, ok := pkgs["glibc-source"]
		Expect(ok).To(BeTrue())
		Expect(pkg.Name).To(Equal("glibc-source"))
		Expect(pkg.Version).To(Equal("2.43"))
		Expect(pkg.Type).To(Equal("source"))
		Expect(pkg.Arch).To(Equal([]string{"linux/amd64"}))
		Expect(pkg.Default).To(BeFalse())
		Expect(pkg.Repo).To(Equal("glibc"))
		Expect(pkg.OriginalRepo).To(Equal("https://sourceware.org/git/glibc.git"))
		Expect(pkg.License).To(Equal("LGPL-2.1-or-later"))
		Expect(pkg.SrcLanguages).To(Equal([]string{"C", "Assembly"}))
		Expect(pkg.Description).To(Equal("Prepared glibc sources and CSU generated headers"))
		Expect(pkg.Digest).To(Equal(exampleSourceImageDigest))
		Expect(pkg.Depends).To(BeEmpty())
	})
})
