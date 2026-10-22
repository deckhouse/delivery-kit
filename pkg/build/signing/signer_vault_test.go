package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeVaultLogin struct {
	path string
	role string
	jwt  string
}

type fakeVault struct {
	*httptest.Server

	publicKeyPEM string
	mu           sync.Mutex
	logins       []fakeVaultLogin
	keyReads     []string
}

func newFakeVault(publicKeyPEM string) *fakeVault {
	v := &fakeVault{publicKeyPEM: publicKeyPEM}
	v.Server = httptest.NewServer(http.HandlerFunc(v.handle))
	return v
}

func (v *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()

	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/auth/"):
		var body map[string]string
		Expect(json.NewDecoder(r.Body).Decode(&body)).To(Succeed())
		v.logins = append(v.logins, fakeVaultLogin{path: r.URL.Path, role: body["role"], jwt: body["jwt"]})
		fmt.Fprintf(w, `{"auth":{"client_token":"s.fake","lease_duration":3600}}`)
	default:
		v.keyReads = append(v.keyReads, r.URL.Path+"|"+r.Header.Get("X-Vault-Token"))
		key := map[string]any{"public_key": v.publicKeyPEM, "name": "rsa-2048"}
		Expect(json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"latest_version": 1,
			"keys":           map[string]any{"1": key},
		}})).To(Succeed())
	}
}

var _ = Describe("NewSigner with hashivault", func() {
	var vault *fakeVault
	var certRef string

	BeforeEach(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		vault = newFakeVault(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
		DeferCleanup(vault.Close)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "vault-test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		certRef = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

		GinkgoT().Setenv("VAULT_ADDR", "http://127.0.0.1:1")
		GinkgoT().Setenv("TRANSIT_SECRET_ENGINE_PATH", "env-transit")
		GinkgoT().Setenv("WERF_VAULT_AUTH_JWT", "env-jwt")
		GinkgoT().Setenv("WERF_VAULT_AUTH_ROLE", "env-role")
		GinkgoT().Setenv("WERF_VAULT_AUTH_PATH", "env-auth")
	})

	It("logs in and reads the key where the Vault options say, not where the environment does", func(ctx SpecContext) {
		_, err := NewSigner(ctx, SignerOptions{
			KeyRef:  "hashivault://engine-key",
			CertRef: certRef,
			Vault: VaultOptions{
				Address:     vault.URL,
				TransitPath: "dh-engine-signer",
				AuthJWT:     "files-jwt",
				AuthRole:    "files-role",
				AuthPath:    "fox",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(vault.logins).To(Equal([]fakeVaultLogin{{path: "/v1/auth/fox/login", role: "files-role", jwt: "files-jwt"}}))
		Expect(vault.keyReads).To(Equal([]string{"/v1/dh-engine-signer/keys/engine-key|s.fake"}))
	})

	It("falls back to the environment for every option left empty", func(ctx SpecContext) {
		GinkgoT().Setenv("VAULT_ADDR", vault.URL)

		_, err := NewSigner(ctx, SignerOptions{
			KeyRef:  "hashivault://engine-key",
			CertRef: certRef,
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(vault.logins).To(Equal([]fakeVaultLogin{{path: "/v1/auth/env-auth/login", role: "env-role", jwt: "env-jwt"}}))
		Expect(vault.keyReads).To(Equal([]string{"/v1/env-transit/keys/engine-key|s.fake"}))
	})

	It("takes the authentication as a whole from the JWT option, without borrowing role or mount from the environment", func(ctx SpecContext) {
		_, err := NewSigner(ctx, SignerOptions{
			KeyRef:  "hashivault://engine-key",
			CertRef: certRef,
			Vault:   VaultOptions{Address: vault.URL, TransitPath: "dh-engine-signer", AuthJWT: "files-jwt"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(vault.logins).To(Equal([]fakeVaultLogin{{path: "/v1/auth/jwt/login", role: "", jwt: "files-jwt"}}),
			"an explicit JWT replaces the environment authentication entirely: the role and the mount do not fall back to it one by one")
	})

	It("keeps the environment authentication when only the address and transit mount are given", func(ctx SpecContext) {
		_, err := NewSigner(ctx, SignerOptions{
			KeyRef:  "hashivault://engine-key",
			CertRef: certRef,
			Vault:   VaultOptions{Address: vault.URL, TransitPath: "dh-engine-signer"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(vault.logins).To(Equal([]fakeVaultLogin{{path: "/v1/auth/env-auth/login", role: "env-role", jwt: "env-jwt"}}))
		Expect(vault.keyReads).To(Equal([]string{"/v1/dh-engine-signer/keys/engine-key|s.fake"}))
	})
})
