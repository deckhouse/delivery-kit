package e2e_build_test

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
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

// imageFilesUnder returns the regular files below dir in the flattened image, keyed by
// their path relative to dir. Files deleted by a later layer are not returned.
func imageFilesUnder(img v1.Image, dir string) map[string][]byte {
	rc := mutate.Extract(img)
	defer rc.Close()

	prefix := strings.Trim(dir, "/") + "/"
	files := make(map[string][]byte)
	reader := tar.NewReader(rc)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return files
		}
		Expect(err).NotTo(HaveOccurred())

		entry := strings.TrimPrefix(strings.TrimPrefix(header.Name, "./"), "/")
		if header.Typeflag != tar.TypeReg || !strings.HasPrefix(entry, prefix) {
			continue
		}

		body, err := io.ReadAll(reader)
		Expect(err).NotTo(HaveOccurred())

		files[strings.TrimPrefix(entry, prefix)] = body
	}
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

func assertGoModuleCaseImages(ctx SpecContext, project *werf.Project) map[string]producedBinarySnapshot {
	const (
		upperModule = "github.com/Masterminds/semver/v3"
		lowerModule = "gopkg.in/yaml.v3"
	)
	negative := cdx.Property{Name: shippedscope.PropertyShipped, Value: "false"}
	unknown := cdx.Property{Name: shippedscope.PropertyBinaries, Value: "unknown"}

	snapshot := make(map[string]producedBinarySnapshot)
	for _, imageName := range []string{"donor", "consumer", "grandchild", "manifest-only"} {
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}}}))

		for module, version := range map[string]string{upperModule: "v3.5.0", lowerModule: "v3.0.0"} {
			comp := sbomtest.FindComponent(bom, module, version)
			Expect(comp).NotTo(BeNil(), "%s must retain component %s", imageName, module)
			Expect(comp.PackageURL).To(Equal("pkg:golang/" + module + "@" + version))
			properties := lo.FromPtr(comp.Properties)

			switch {
			case imageName == "manifest-only":
				Expect(slices.Contains(properties, negative) || slices.Contains(properties, unknown)).To(BeTrue(), "%s must mark %s not shipped", imageName, module)
			case module == upperModule || imageName == "donor":
				Expect(properties).NotTo(ContainElement(negative), "%s must ship %s", imageName, module)
				Expect(occurrencesOf(comp)).To(ContainElement(HaveField("AdditionalContext", MatchRegexp(`^werf:binary:v1:sha256:[0-9a-f]{64}$`))), "%s must carry binary evidence for %s", imageName, module)
			default:
				Expect(properties).To(ContainElement(negative), "%s must mark %s not shipped", imageName, module)
			}
		}

		for _, comp := range lo.FromPtr(bom.Components) {
			if !strings.HasPrefix(comp.PackageURL, "pkg:golang/") {
				continue
			}
			properties := lo.FromPtr(comp.Properties)
			if imageName == "manifest-only" && !slices.Contains(properties, unknown) {
				Expect(properties).To(ContainElement(negative), "%s must mark %s not shipped", imageName, comp.PackageURL)
			}
			snapshot[imageName+"/"+comp.PackageURL] = producedBinarySnapshot{
				Shipped:     !slices.Contains(properties, negative),
				Unknown:     slices.Contains(properties, unknown),
				Occurrences: occurrencesOf(&comp),
			}
		}
	}

	return snapshot
}

const (
	jsBundleEvidencePrefix = "werf:js-bundle:v1:"

	jsMainOwnerPURL    = "pkg:npm/pretty-bytes@6.1.1"
	jsLazyOwnerPURL    = "pkg:npm/escape-string-regexp@5.0.0"
	jsTreeShakenPURL   = "pkg:npm/lodash-es@4.17.21"
	jsMainOwnerMarker  = "Mibit"
	jsLazyOwnerMarker  = `\\x2d`
	jsTreeShakenMarker = "__lodash_hash_undefined__"
)

type jsBundleSnapshot struct {
	Shipped     bool
	Occurrences []cdx.EvidenceOccurrence
}

// assertJavaScriptBundleOutputs proves the fixture is a valid oracle before any SBOM is
// read. dist-baseline is built with an emptied environment, so without the observer: dist
// must match it byte for byte. Each chunk must hold only its owner's code, and the
// tree-shaken package must be installed but not emitted. Returns each chunk's digest.
func assertJavaScriptBundleOutputs(ctx SpecContext, project *werf.Project, repoPath string) map[string]string {
	repo := os.Getenv("WERF_REPO")
	Expect(repo).NotTo(BeEmpty())
	filesOf := func(imageName, dir string) map[string][]byte {
		return imageFilesUnder(pullImage(ctx, repo+"@"+stagesImageDigestOf(ctx, project, imageName)), dir)
	}

	donor := filesOf("donor", "/app")
	pruned := filesOf("pruned-donor", "/app")
	dist := filesUnder(donor, "dist")
	Expect(lo.Keys(dist)).To(ConsistOf("main.js", "lazy.js"))
	Expect(filesUnder(donor, "dist-baseline")).To(Equal(dist), "the observer must not change emitted bytes")
	Expect(filesUnder(pruned, "moved-dist")).To(Equal(dist))
	Expect(filesUnder(pruned, "dist")).To(BeEmpty())
	Expect(filesUnder(pruned, "dist-baseline")).To(Equal(dist))
	Expect(filesUnder(pruned, "node_modules")).To(BeEmpty())

	for _, input := range []string{"package.json", "package-lock.json", "vite.config.js", "src/main.js", "src/lazy.js"} {
		body, err := os.ReadFile(filepath.Join(repoPath, input))
		Expect(err).NotTo(HaveOccurred())
		Expect(donor).To(HaveKeyWithValue(input, body), "the build must not rewrite %s", input)
	}

	Expect(string(donor["node_modules/pretty-bytes/index.js"])).To(ContainSubstring(jsMainOwnerMarker))
	Expect(string(donor["node_modules/escape-string-regexp/index.js"])).To(ContainSubstring(jsLazyOwnerMarker))
	Expect(string(donor["node_modules/lodash-es/_hashSet.js"])).To(ContainSubstring(jsTreeShakenMarker))
	main, lazy := string(dist["main.js"]), string(dist["lazy.js"])
	Expect(main).To(ContainSubstring(jsMainOwnerMarker))
	Expect(main).NotTo(ContainSubstring(jsLazyOwnerMarker))
	Expect(lazy).To(ContainSubstring(jsLazyOwnerMarker))
	Expect(lazy).NotTo(ContainSubstring(jsMainOwnerMarker))
	Expect(main + lazy).NotTo(ContainSubstring(jsTreeShakenMarker))

	Expect(filesOf("one-chunk", "/srv")).To(Equal(map[string][]byte{"bundle.js": dist["main.js"]}))
	Expect(filesOf("grandchild", "/www")).To(Equal(map[string][]byte{"app.js": dist["main.js"]}))
	Expect(filesOf("all-chunks", "/srv/dist")).To(Equal(dist))
	Expect(filesOf("lock-only", "/app")).To(Equal(map[string][]byte{"package-lock.json": donor["package-lock.json"]}))

	return lo.MapValues(dist, func(body []byte, _ string) string { return digestOfString(string(body)) })
}

func filesUnder(files map[string][]byte, dir string) map[string][]byte {
	under := make(map[string][]byte)
	for path, body := range files {
		if rel, ok := strings.CutPrefix(path, dir+"/"); ok {
			under[rel] = body
		}
	}
	return under
}

func assertJavaScriptBundleImages(ctx SpecContext, project *werf.Project, chunks map[string]string) map[string]jsBundleSnapshot {
	negative := cdx.Property{Name: shippedscope.PropertyShipped, Value: "false"}
	owners := map[string]string{jsMainOwnerPURL: "main.js", jsLazyOwnerPURL: "lazy.js", jsTreeShakenPURL: ""}

	snapshot := make(map[string]jsBundleSnapshot)
	for imageName, present := range map[string][]string{
		"donor":        {"main.js", "lazy.js"},
		"pruned-donor": {"main.js", "lazy.js"},
		"one-chunk":    {"main.js"},
		"grandchild":   {"main.js"},
		"all-chunks":   {"main.js", "lazy.js"},
		"lock-only":    {},
	} {
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}}}))

		for _, comp := range lo.FromPtr(bom.Components) {
			if len(jsBundleOccurrences(&comp)) == 0 {
				continue
			}
			Expect(owners).To(HaveKey(comp.PackageURL), "%s: %s must not carry bundle evidence", imageName, comp.PackageURL)
		}

		for purl, chunk := range owners {
			comp := sbomtest.FindComponentByPURL(bom, purl)
			Expect(comp).NotTo(BeNil(), "%s must retain component %s", imageName, purl)
			Expect(comp.PackageURL).To(Equal(purl))
			properties := lo.FromPtr(comp.Properties)
			occurrences := jsBundleOccurrences(comp)

			if chunk == "" {
				Expect(occurrences).To(BeEmpty(), "%s: tree-shaken %s must not carry bundle evidence", imageName, purl)
			}
			own := And(
				HaveField("Location", "/app/dist/"+chunk),
				HaveField("AdditionalContext", jsBundleEvidencePrefix+chunks[chunk]),
			)
			for _, occurrence := range occurrences {
				Expect(occurrence).To(own, "%s: %s evidence must name only its own chunk", imageName, purl)
			}

			switch {
			case chunk != "" && slices.Contains(present, chunk):
				Expect(occurrences).To(ContainElement(own), "%s: %s must carry evidence for %s", imageName, purl, chunk)
				Expect(properties).NotTo(ContainElement(negative), "%s must ship %s", imageName, purl)
			case imageName == "donor":
				Expect(properties).NotTo(ContainElement(negative), "the donor installed %s", purl)
			case imageName == "pruned-donor":
				// Pruning removed the tree-shaken package's files, and no bundle evidence can
				// stand in for them, so its verdict there is left to the contract for unknown.
			default:
				Expect(properties).To(ContainElement(negative), "%s must mark %s not shipped", imageName, purl)
			}

			snapshot[imageName+"/"+purl] = jsBundleSnapshot{Shipped: !slices.Contains(properties, negative), Occurrences: occurrencesOf(comp)}
		}
	}

	return snapshot
}

func jsBundleOccurrences(comp *cdx.Component) []cdx.EvidenceOccurrence {
	return lo.Filter(occurrencesOf(comp), func(occurrence cdx.EvidenceOccurrence, _ int) bool {
		return strings.HasPrefix(occurrence.AdditionalContext, "werf:js-bundle:")
	})
}
