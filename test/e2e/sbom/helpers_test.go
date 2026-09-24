package e2e_build_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var multiplatformSbomPlatforms = []string{"linux/amd64", "linux/arm64"}

func insecureRemoteOptions(ctx SpecContext) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	}
}

func pullSbomFallbackIndexManifests(ctx SpecContext, repo, parentDigest string) ([]v1.Descriptor, bool) {
	tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(parentDigest), name.Insecure)
	Expect(err).NotTo(HaveOccurred())

	idx, err := remote.Index(tagRef, insecureRemoteOptions(ctx)...)
	if err != nil {
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == 404 {
			return nil, false
		}
		Expect(err).NotTo(HaveOccurred())
	}

	im, err := idx.IndexManifest()
	Expect(err).NotTo(HaveOccurred())

	var dsseDescs []v1.Descriptor
	for _, desc := range im.Manifests {
		if desc.ArtifactType != attestation.DSSEMediaType && desc.ArtifactType != attestation.BundleMediaType {
			continue
		}
		// Attestations of other kinds (e.g. an image-level OpenVEX document) share
		// these artifact types and legitimately sit on the same digest, so entries
		// annotated with another predicate are not SBOM artifacts. Entries with no
		// predicate annotation predate the annotation and are counted as SBOMs.
		predicate, annotated := desc.Annotations[artifact.PredicateTypeAnnotation]
		if annotated && !slices.Contains(sbomImage.CycloneDXPredicateTypes, predicate) {
			continue
		}
		dsseDescs = append(dsseDescs, desc)
	}
	return dsseDescs, true
}

func fetchSingleSbomArtifact(ctx SpecContext, repo, parentDigest string) (v1.Descriptor, []byte) {
	dsseDescs, found := pullSbomFallbackIndexManifests(ctx, repo, parentDigest)
	Expect(found).To(BeTrue(), "no fallback tag for digest %s", parentDigest)
	Expect(dsseDescs).To(HaveLen(1), "expected exactly one SBOM artifact for digest %s", parentDigest)

	artifactRef, err := name.NewDigest(repo+"@"+dsseDescs[0].Digest.String(), name.Insecure)
	Expect(err).NotTo(HaveOccurred())

	img, err := remote.Image(artifactRef, insecureRemoteOptions(ctx)...)
	Expect(err).NotTo(HaveOccurred())

	layers, err := img.Layers()
	Expect(err).NotTo(HaveOccurred())
	Expect(layers).To(HaveLen(1))

	rc, err := layers[0].Compressed()
	Expect(err).NotTo(HaveOccurred())
	defer rc.Close()

	payload, err := io.ReadAll(rc)
	Expect(err).NotTo(HaveOccurred())

	return dsseDescs[0], payload
}

func expectNoSbomArtifact(ctx SpecContext, repo, parentDigest string) {
	dsseDescs, found := pullSbomFallbackIndexManifests(ctx, repo, parentDigest)
	if !found {
		return
	}
	Expect(dsseDescs).To(BeEmpty(), "no SBOM artifact must be attached to the index digest %s", parentDigest)
}

// stagesImageDigestOf resolves the digest of the image's last stage in the stages
// repo, which is what artifacts in the stages and cache repos are attached to.
func stagesImageDigestOf(ctx SpecContext, werfProject *werf.Project, imageName string) string {
	stagesRepo := os.Getenv("WERF_REPO")
	Expect(stagesRepo).NotTo(BeEmpty())

	tagRef, err := name.NewTag(stagesRepo+":"+stageTagOf(ctx, werfProject, imageName, nil), name.Insecure)
	Expect(err).NotTo(HaveOccurred())

	desc, err := remote.Get(tagRef, insecureRemoteOptions(ctx)...)
	Expect(err).NotTo(HaveOccurred())

	return desc.Digest.String()
}

func mustExtractInTotoSubjectDigest(dsseEnvelope []byte) string {
	var envelope struct {
		Payload []byte `json:"payload"`
	}
	Expect(json.Unmarshal(dsseEnvelope, &envelope)).To(Succeed())

	var statement struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	Expect(json.Unmarshal(envelope.Payload, &statement)).To(Succeed())
	Expect(statement.Subject).To(HaveLen(1))

	hex, hasSha256 := statement.Subject[0].Digest["sha256"]
	Expect(hasSha256).To(BeTrue(), "in-toto subject must carry a sha256 digest")
	return "sha256:" + hex
}
