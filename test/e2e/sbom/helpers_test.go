package e2e_build_test

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
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

	tagRef, err := name.NewTag(stagesRepo+":"+stageTagOf(ctx, werfProject, imageName), name.Insecure)
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

type producedBinarySnapshot struct {
	Shipped     bool
	Unknown     bool
	Occurrences []cdx.EvidenceOccurrence
}

func assertProducedBinaryImages(ctx SpecContext, project *werf.Project) map[string]producedBinarySnapshot {
	snapshot := make(map[string]producedBinarySnapshot)
	for _, imageName := range []string{"donor", "consumer", "grandchild", "manifest-only"} {
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}}}))
		for module, version := range map[string]string{
			"github.com/spf13/cobra":               "v1.5.0",
			"github.com/spf13/pflag":               "v1.0.5",
			"github.com/inconshreveable/mousetrap": "v1.1.0",
			"gopkg.in/yaml.v3":                     "v3.0.0",
		} {
			comp := sbomtest.FindComponent(bom, module, version)
			Expect(comp).NotTo(BeNil(), "%s must retain component %s", imageName, module)
			shipped := imageName != "manifest-only" && module != "github.com/inconshreveable/mousetrap" && (imageName == "donor" || module != "gopkg.in/yaml.v3")
			properties := lo.FromPtr(comp.Properties)
			negative := cdx.Property{Name: shippedscope.PropertyShipped, Value: "false"}
			unknown := cdx.Property{Name: shippedscope.PropertyBinaries, Value: "unknown"}
			if module == "github.com/inconshreveable/mousetrap" {
				Expect(properties).To(ContainElement(unknown), "the pinned base has this same PURL without binary evidence")
				Expect(properties).NotTo(ContainElement(negative), "local checked-empty cannot erase an unknown inherited origin")
			} else if shipped {
				Expect(properties).NotTo(ContainElement(negative), "%s must ship %s", imageName, module)
				Expect(comp.Evidence).NotTo(BeNil())
				Expect(lo.FromPtr(comp.Evidence.Occurrences)).To(ContainElement(HaveField("AdditionalContext", MatchRegexp(`^werf:binary:v1:sha256:[0-9a-f]{64}$`))))
			} else {
				Expect(properties).To(ContainElement(negative), "%s must mark %s not shipped", imageName, module)
			}
			var occurrences []cdx.EvidenceOccurrence
			if comp.Evidence != nil {
				occurrences = lo.FromPtr(comp.Evidence.Occurrences)
			}
			snapshot[imageName+"/"+module] = producedBinarySnapshot{Shipped: !slices.Contains(properties, negative), Unknown: slices.Contains(properties, unknown), Occurrences: occurrences}
		}
	}
	return snapshot
}

func shippedProperty(comp *cdx.Component) (string, bool) {
	for _, property := range lo.FromPtr(comp.Properties) {
		if property.Name == shippedscope.PropertyShipped {
			return property.Value, true
		}
	}

	return "", false
}

func pullImage(ctx SpecContext, imageRef string) v1.Image {
	ref, err := name.NewDigest(imageRef, name.Insecure)
	Expect(err).NotTo(HaveOccurred())

	img, err := remote.Image(ref, insecureRemoteOptions(ctx)...)
	Expect(err).NotTo(HaveOccurred())

	return img
}

// readImageFile returns a regular file as the flattened image holds it: the topmost layer
// carrying the path wins.
func readImageFile(img v1.Image, path string) []byte {
	layers, err := img.Layers()
	Expect(err).NotTo(HaveOccurred())

	want := strings.TrimPrefix(path, "/")
	for i := len(layers) - 1; i >= 0; i-- {
		if body, found := readLayerFile(layers[i], want); found {
			return body
		}
	}

	Fail(fmt.Sprintf("file %s not found in image", path))
	return nil
}

func readLayerFile(layer v1.Layer, want string) ([]byte, bool) {
	rc, err := layer.Uncompressed()
	Expect(err).NotTo(HaveOccurred())
	defer rc.Close()

	reader := tar.NewReader(rc)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil, false
		}
		Expect(err).NotTo(HaveOccurred())

		entry := strings.TrimPrefix(strings.TrimPrefix(header.Name, "./"), "/")
		if entry != want || header.Typeflag != tar.TypeReg {
			continue
		}

		body, err := io.ReadAll(reader)
		Expect(err).NotTo(HaveOccurred())

		return body, true
	}
}

// ospmComponent finds the package pm installed under the given catalog version. The
// base image's own packages are also cataloged under the version the base was built
// with, so the qualifier tells the two records of one package apart.
func ospmComponent(bom *cdx.BOM, name, containerFactoryVersion string) *cdx.Component {
	for _, comp := range lo.FromPtr(bom.Components) {
		if comp.Name == name && strings.HasPrefix(comp.PackageURL, "pkg:generic/") &&
			strings.Contains(comp.PackageURL, "containerfactoryversion="+containerFactoryVersion) {
			return &comp
		}
	}

	return nil
}

func occurrencesOf(comp *cdx.Component) []cdx.EvidenceOccurrence {
	if comp == nil || comp.Evidence == nil {
		return nil
	}

	return lo.FromPtr(comp.Evidence.Occurrences)
}

func locationOf(occurrence cdx.EvidenceOccurrence, _ int) string {
	return occurrence.Location
}

func stableBOM(bom *cdx.BOM) *cdx.BOM {
	bom.SerialNumber = ""
	if bom.Metadata != nil {
		bom.Metadata.Timestamp = ""
	}

	return bom
}
