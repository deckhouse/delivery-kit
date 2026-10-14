package stage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/stretchr/testify/require"

	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
)

func newSignFilesTestSigner(t *testing.T, cn string) *signing.Signer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	encryptedKey, err := encrypted.Encrypt(keyDER, nil)
	require.NoError(t, err)

	signer, err := signing.NewSigner(context.Background(), signing.SignerOptions{
		KeyRef:  base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: signver.PrivateKeyPemType, Bytes: encryptedKey})),
		CertRef: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
	})
	require.NoError(t, err)
	return signer
}

func newSignFilesTestStage(signer *signing.Signer, paths ...string) *SignFilesStage {
	imageConfig := &config.StapelImageBase{}
	for _, p := range paths {
		imageConfig.Sign = append(imageConfig.Sign, &config.Sign{Path: p, After: "install"})
	}
	options := signing.NewFilesSigningOptions(signer)
	options.Enabled = true
	return GenerateSignFilesAfterInstallStage(imageConfig, options, &BaseStageOptions{})
}

func TestSignFilesStage_DigestChangesWithPathsAndCertificate(t *testing.T) {
	ctx := context.Background()
	signerA := newSignFilesTestSigner(t, "a")
	signerB := newSignFilesTestSigner(t, "b")

	base, err := newSignFilesTestStage(signerA, "/out/x").GetDependencies(ctx, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	same, err := newSignFilesTestStage(signerA, "/out/x").GetDependencies(ctx, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, base, same, "the digest must be stable for the same paths and signer")

	otherPath, err := newSignFilesTestStage(signerA, "/out/y").GetDependencies(ctx, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	require.NotEqual(t, base, otherPath, "a different signed path must change the digest")

	otherCert, err := newSignFilesTestStage(signerB, "/out/x").GetDependencies(ctx, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	require.NotEqual(t, base, otherCert, "a different signing certificate must change the digest")

	content, err := newSignFilesTestStage(signerA, "/out/x").GetContentDependencies(ctx, nil, nil)
	require.NoError(t, err)
	require.Equal(t, base, content, "the content digest must be the same input set")
}

func TestSignFilesStage_NotGeneratedWithoutMatchingDirective(t *testing.T) {
	signer := newSignFilesTestSigner(t, "a")

	imageConfig := &config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", Before: "install"}}}
	options := signing.NewFilesSigningOptions(signer)
	options.Enabled = true
	require.Nil(t, GenerateSignFilesAfterInstallStage(imageConfig, options, &BaseStageOptions{}))
	require.NotNil(t, GenerateSignFilesBeforeInstallStage(imageConfig, options, &BaseStageOptions{}))

	options.Enabled = false
	require.Nil(t, GenerateSignFilesBeforeInstallStage(imageConfig, options, &BaseStageOptions{}))
}
