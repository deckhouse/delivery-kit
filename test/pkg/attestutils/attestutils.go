package attestutils

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

// SigningKeyPair is the on-disk key material a signing e2e scenario needs:
// the sigstore-encrypted private key, its bare public key and the leaf cert.
type SigningKeyPair struct {
	KeyPath    string
	PubKeyPath string
	CertPath   string
}

// GenerateSigningKeyPairWithCert produces key material accepted by
// --sign-key/--sign-cert and a public key file for verification.
func GenerateSigningKeyPairWithCert(dir string) SigningKeyPair {
	certs := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
		KeyType:  cert_utils.KeyType_ED25519,
		PassFunc: cryptoutils.SkipPassword,
		TmpDir:   dir,
	})

	pubKeyPath := cert_utils.FormatPublicKeyToPEMFile(dir, certs.PrivKey.Public())

	return SigningKeyPair{KeyPath: certs.PrivRef, PubKeyPath: pubKeyPath, CertPath: certs.LeafRef}
}

// FindArtifactDescriptor returns the first fallback-index entry of the given
// artifact type attached to parentDigest, or nil when the index or entry is
// absent.
func FindArtifactDescriptor(ctx context.Context, repo, parentDigest, artifactType string) *v1.Descriptor {
	return findDescriptor(ctx, repo, parentDigest, func(desc v1.Descriptor) bool {
		return desc.ArtifactType == artifactType
	})
}

// FindArtifactDescriptorByPredicate returns the fallback-index entry of the
// given artifact type carrying the predicate-type annotation, or nil.
func FindArtifactDescriptorByPredicate(ctx context.Context, repo, parentDigest, artifactType, predicateType string) *v1.Descriptor {
	return findDescriptor(ctx, repo, parentDigest, func(desc v1.Descriptor) bool {
		return desc.ArtifactType == artifactType && desc.Annotations[artifact.PredicateTypeAnnotation] == predicateType
	})
}

func findDescriptor(ctx context.Context, repo, parentDigest string, match func(v1.Descriptor) bool) *v1.Descriptor {
	tagRef, err := name.NewTag(repo+":"+artifact.FallbackTag(parentDigest), name.Insecure)
	gomega.ExpectWithOffset(2, err).NotTo(gomega.HaveOccurred())

	idx, err := remote.Index(tagRef, remoteOptions(ctx)...)
	if err != nil {
		return nil
	}

	im, err := idx.IndexManifest()
	gomega.ExpectWithOffset(2, err).NotTo(gomega.HaveOccurred())

	for _, desc := range im.Manifests {
		if match(desc) {
			found := desc
			return &found
		}
	}
	return nil
}

// FetchArtifactLayerContent returns the payload of the artifact image
// identified by digest.
func FetchArtifactLayerContent(ctx context.Context, repo, digest string) []byte {
	imgRef, err := name.NewDigest(repo+"@"+digest, name.Insecure)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())

	img, err := remote.Image(imgRef, remoteOptions(ctx)...)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())

	layers, err := img.Layers()
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	gomega.ExpectWithOffset(1, layers).NotTo(gomega.BeEmpty())

	rc, err := layers[0].Compressed()
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	defer rc.Close()

	content, err := io.ReadAll(rc)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred())
	return content
}

func remoteOptions(ctx context.Context) []remote.Option {
	return []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.Anonymous)}
}

// CosignVerifyOptions describes one offline stock-cosign verification.
type CosignVerifyOptions struct {
	Repo string

	// Digest identifies what to verify: an image manifest digest, or an image
	// index digest for image-level attestations such as OpenVEX.
	Digest string

	// PubKeyPath is the bare public key the attestation is verified against.
	PubKeyPath string

	// PredicateType is the cosign --type value, e.g. "cyclonedx" or "openvex".
	PredicateType string

	// TmpDir holds the generated empty trusted root.
	TmpDir string
}

// RunCosignOfflineVerify verifies an attestation with stock cosign, fully
// offline, the way a client holding only the public key would:
//
//	cosign trusted-root create --out tr.json
//	cosign verify-attestation --new-bundle-format --trusted-root tr.json \
//	  --insecure-ignore-tlog=true --key pub.pem --type <predicate> <image>@<digest>
//
// The spec skips when no cosign binary is available (env WERF_TEST_COSIGN_BIN or
// PATH): CI runners carry no cosign, so this check is a bonus over the
// in-process DSSE verification the suites always perform.
func RunCosignOfflineVerify(ctx context.Context, opts CosignVerifyOptions) {
	cosignBin := os.Getenv("WERF_TEST_COSIGN_BIN")
	if cosignBin == "" {
		var err error
		cosignBin, err = exec.LookPath("cosign")
		if err != nil {
			ginkgo.Skip("cosign binary not available: set WERF_TEST_COSIGN_BIN or add cosign to PATH")
		}
	}

	trustedRootPath := filepath.Join(opts.TmpDir, "cosign-trusted-root.json")
	createCmd := exec.CommandContext(ctx, cosignBin, "trusted-root", "create", "--out", trustedRootPath)
	createOut, err := createCmd.CombinedOutput()
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred(), "cosign trusted-root create failed: %s", string(createOut))

	verifyCmd := exec.CommandContext(ctx, cosignBin, "verify-attestation",
		"--new-bundle-format",
		"--trusted-root", trustedRootPath,
		"--insecure-ignore-tlog=true",
		"--key", opts.PubKeyPath,
		"--type", opts.PredicateType,
		opts.Repo+"@"+opts.Digest,
	)
	verifyCmd.Env = append(os.Environ(), "COSIGN_ALLOW_INSECURE_REGISTRY=true")
	verifyOut, err := verifyCmd.CombinedOutput()
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred(), "cosign verify-attestation failed: %s", string(verifyOut))
	gomega.ExpectWithOffset(1, string(verifyOut)).To(gomega.ContainSubstring("verified"))
}
