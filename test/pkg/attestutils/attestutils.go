package attestutils

import (
	"context"
	"io"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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
