package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sigstore Bundle", func() {
	var (
		privateKey *ecdsa.PrivateKey
		envelope   []byte
	)

	BeforeEach(func() {
		var err error
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		envelope = []byte(`{"payload":"dGVzdA==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEUCIQC="}]}`)
	})

	Describe("WrapInBundle / UnwrapBundle round-trip", func() {
		It("preserves the DSSE envelope through wrap and unwrap", func() {
			bundleJSON, err := WrapInBundle(envelope, privateKey.Public())
			Expect(err).NotTo(HaveOccurred())

			recovered, err := UnwrapBundle(bundleJSON)
			Expect(err).NotTo(HaveOccurred())

			var orig, got map[string]interface{}
			Expect(json.Unmarshal(envelope, &orig)).To(Succeed())
			Expect(json.Unmarshal(recovered, &got)).To(Succeed())
			Expect(got["payload"]).To(Equal(orig["payload"]))
			Expect(got["payloadType"]).To(Equal(orig["payloadType"]))
		})
	})

	Describe("golden fixture structural equality", func() {
		It("produces JSON with the same key structure as the cosign golden bundle", func() {
			goldenBytes, err := os.ReadFile("testdata/cosign-golden-bundle.json")
			Expect(err).NotTo(HaveOccurred())

			bundleJSON, err := WrapInBundle(envelope, privateKey.Public())
			Expect(err).NotTo(HaveOccurred())

			goldenKeys := collectJSONKeys(goldenBytes)
			producedKeys := collectJSONKeys(bundleJSON)
			Expect(producedKeys).To(Equal(goldenKeys))
		})
	})

	Describe("UnwrapBundle on golden fixture", func() {
		It("extracts a valid DSSE envelope from the cosign-produced bundle", func() {
			goldenBytes, err := os.ReadFile("testdata/cosign-golden-bundle.json")
			Expect(err).NotTo(HaveOccurred())

			envelopeJSON, err := UnwrapBundle(goldenBytes)
			Expect(err).NotTo(HaveOccurred())

			var env map[string]interface{}
			Expect(json.Unmarshal(envelopeJSON, &env)).To(Succeed())
			Expect(env["payloadType"]).To(Equal("application/vnd.in-toto+json"))
			Expect(env["payload"]).NotTo(BeEmpty())
			Expect(env["signatures"]).NotTo(BeEmpty())
		})
	})

	Describe("hint derivation", func() {
		It("produces base64(sha256(DER SPKI)) of the public key", func() {
			hint, err := publicKeyHint(privateKey.Public())
			Expect(err).NotTo(HaveOccurred())

			decoded, err := base64.StdEncoding.DecodeString(hint)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded).To(HaveLen(32))

			der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
			Expect(err).NotTo(HaveOccurred())
			expected := sha256.Sum256(der)
			Expect(decoded).To(Equal(expected[:]))
		})
	})

	DescribeTable("error handling",
		func(input []byte, errSubstring string) {
			_, err := UnwrapBundle(input)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(errSubstring))
		},
		Entry("truncated JSON", []byte(`{"media`), "unmarshal sigstore bundle"),
		Entry("wrong mediaType", []byte(`{"mediaType":"wrong","verificationMaterial":{},"dsseEnvelope":{}}`), "unsupported bundle media type: wrong"),
		Entry("empty input", []byte{}, "unmarshal sigstore bundle"),
	)

	It("WrapInBundle rejects invalid envelope JSON", func() {
		_, err := WrapInBundle([]byte(`not json`), privateKey.Public())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("parse dsse envelope"))
	})
})

func collectJSONKeys(data []byte) []string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil
	}

	var keys []string
	for k, v := range obj {
		keys = append(keys, k)
		nested := collectJSONKeys(v)
		for _, nk := range nested {
			keys = append(keys, k+"."+nk)
		}
	}

	sortStrings(keys)
	return keys
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
