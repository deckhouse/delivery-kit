package e2e_build_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	pmreader "fox.flant.com/deckhouse/container-base/pm.git/sbom"
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
	"gopkg.in/yaml.v3"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
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

const (
	yarnPnPProjectCache = "/app/.yarn/cache"
	yarnPnPGlobalCache  = "/root/.yarn/berry/cache"
	yarnPnPUnplugged    = "/app/.yarn/unplugged/escape-string-regexp-npm-4.0.0-"

	yarnPnPShippedPURL   = "pkg:npm/ms@2.1.3"
	yarnPnPUnpluggedPURL = "pkg:npm/escape-string-regexp@4.0.0"
)

var yarnPnPLockedPURLs = map[string]string{
	"@sindresorhus/is@npm:4.6.0":     "pkg:npm/%40sindresorhus/is@4.6.0",
	"debug@npm:2.6.9":                "pkg:npm/debug@2.6.9",
	"escape-string-regexp@npm:4.0.0": yarnPnPUnpluggedPURL,
	"ms@npm:2.0.0":                   "pkg:npm/ms@2.0.0",
	"ms@npm:2.1.3":                   yarnPnPShippedPURL,
}

type yarnPnPSnapshot struct {
	Shipped     bool
	Occurrences []cdx.EvidenceOccurrence
}

// assertYarnPnPOutputs proves the fixture is a valid oracle before any SBOM is read: each
// donor holds every locked package as a cache zip whose SHA-512 is the lock checksum, in
// the project cache or the default global one, and each consumer holds exactly what it
// imported. Returns, per donor, the occurrence each locked package's zip must produce.
func assertYarnPnPOutputs(ctx SpecContext, project *werf.Project, repoPath string) map[string]map[string]cdx.EvidenceOccurrence {
	repo := os.Getenv("WERF_REPO")
	Expect(repo).NotTo(BeEmpty())
	images := make(map[string]v1.Image)
	filesOf := func(imageName, dir string) map[string][]byte {
		if _, ok := images[imageName]; !ok {
			images[imageName] = pullImage(ctx, repo+"@"+stagesImageDigestOf(ctx, project, imageName))
		}
		return imageFilesUnder(images[imageName], dir)
	}

	lock, err := os.ReadFile(filepath.Join(repoPath, "yarn.lock"))
	Expect(err).NotTo(HaveOccurred())
	globalLock, err := os.ReadFile(filepath.Join(repoPath, "global", "yarn.lock"))
	Expect(err).NotTo(HaveOccurred())
	Expect(globalLock).To(Equal(lock))

	var entries map[string]struct {
		Resolution string `yaml:"resolution"`
		Checksum   string `yaml:"checksum"`
	}
	Expect(yaml.Unmarshal(lock, &entries)).To(Succeed())
	checksums := make(map[string]string)
	for _, entry := range entries {
		purl, ok := yarnPnPLockedPURLs[entry.Resolution]
		if !ok {
			continue
		}
		_, checksum, found := strings.Cut(entry.Checksum, "/")
		Expect(found).To(BeTrue(), "%s: checksum %q carries no cache key", entry.Resolution, entry.Checksum)
		checksums[checksum] = purl
	}
	Expect(lo.Values(checksums)).To(ConsistOf(lo.Values(yarnPnPLockedPURLs)))

	archivesIn := func(imageName, dir string) map[string]cdx.EvidenceOccurrence {
		archives := make(map[string]cdx.EvidenceOccurrence)
		for file, body := range filesOf(imageName, dir) {
			if !strings.HasSuffix(file, ".zip") {
				continue
			}
			sum := sha512.Sum512(body)
			purl, ok := checksums[hex.EncodeToString(sum[:])]
			Expect(ok).To(BeTrue(), "%s: %s/%s matches no lock checksum", imageName, dir, file)
			archives[purl] = cdx.EvidenceOccurrence{Location: dir + "/" + file, AdditionalContext: digestOfString(string(body))}
		}
		Expect(lo.Keys(archives)).To(ConsistOf(lo.Values(yarnPnPLockedPURLs)), "%s must cache a zip of every locked package in %s", imageName, dir)
		return archives
	}

	donor := filesOf("donor", "/app")
	Expect(donor).To(HaveKeyWithValue("yarn.lock", lock), "the install must not rewrite the lock")
	Expect(donor).To(HaveKey(".pnp.cjs"))
	Expect(filesUnder(donor, "node_modules")).To(BeEmpty(), "the PnP linker writes no node_modules")
	Expect(donor).To(HaveKey(MatchRegexp(`^\.yarn/unplugged/escape-string-regexp-npm-4\.0\.0-[^/]+/node_modules/escape-string-regexp/index\.js$`)))
	archives := archivesIn("donor", yarnPnPProjectCache)

	global := filesOf("donor-global", "/app")
	Expect(global).To(HaveKey(".pnp.cjs"))
	Expect(filesUnder(global, ".yarn/cache")).To(BeEmpty(), "the default global cache leaves no project cache")
	globalArchives := archivesIn("donor-global", yarnPnPGlobalCache)

	shippedZip := strings.TrimPrefix(archives[yarnPnPShippedPURL].Location, yarnPnPProjectCache+"/")
	imported := map[string][]byte{
		"index.js":                  donor["index.js"],
		"package.json":              donor["package.json"],
		".pnp.cjs":                  donor[".pnp.cjs"],
		".yarn/cache/" + shippedZip: donor[".yarn/cache/"+shippedZip],
	}
	Expect(filesOf("consumer-one", "/srv/app")).To(Equal(imported))
	Expect(filesOf("grandchild", "/opt/app")).To(Equal(imported))
	Expect(filesOf("lock-only", "/app")).To(Equal(map[string][]byte{"yarn.lock": lock}))

	return map[string]map[string]cdx.EvidenceOccurrence{"donor": archives, "donor-global": globalArchives}
}

func assertYarnPnPImages(ctx SpecContext, project *werf.Project, archives map[string]map[string]cdx.EvidenceOccurrence) map[string]yarnPnPSnapshot {
	negative := cdx.Property{Name: shippedscope.PropertyShipped, Value: "false"}

	snapshot := make(map[string]yarnPnPSnapshot)
	for _, imageName := range []string{"donor", "donor-global", "consumer-one", "grandchild", "lock-only"} {
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}}}))
		donorArchives, isDonor := archives[imageName]

		for _, comp := range lo.FromPtr(bom.Components) {
			properties := lo.FromPtr(comp.Properties)
			switch {
			case isDonor:
				Expect(properties).NotTo(ContainElement(negative), "%s installed %s", imageName, comp.PackageURL)
			case !strings.HasPrefix(comp.PackageURL, "pkg:npm/") || strings.HasPrefix(comp.PackageURL, "pkg:npm/yarn-pnp@") || len(occurrencesOf(&comp)) == 0:
			case imageName != "lock-only" && comp.PackageURL == yarnPnPShippedPURL:
			default:
				Expect(properties).To(ContainElement(negative), "%s carries no file of %s", imageName, comp.PackageURL)
			}
		}

		for _, purl := range yarnPnPLockedPURLs {
			comp := sbomtest.FindComponentByPURL(bom, purl)
			Expect(comp).NotTo(BeNil(), "%s must retain component %s", imageName, purl)
			Expect(comp.PackageURL).To(Equal(purl))
			properties := lo.FromPtr(comp.Properties)
			occurrences := occurrencesOf(comp)

			switch {
			case isDonor:
				Expect(occurrences).To(ContainElement(donorArchives[purl]), "%s must evidence %s by its cache zip", imageName, purl)
				if purl == yarnPnPUnpluggedPURL {
					Expect(occurrences).To(ContainElement(And(
						HaveField("Location", HavePrefix(yarnPnPUnplugged)),
						HaveField("AdditionalContext", MatchRegexp(`^sha256:[0-9a-f]{64}$`)),
					)), "%s must evidence the unplugged %s by its node_modules files", imageName, purl)
				}
				Expect(properties).NotTo(ContainElement(negative), "%s must ship %s", imageName, purl)
			case imageName != "lock-only" && purl == yarnPnPShippedPURL:
				Expect(occurrences).To(ContainElement(archives["donor"][purl]), "%s must keep the zip evidence of %s", imageName, purl)
				Expect(properties).NotTo(ContainElement(negative), "%s imported the zip of %s", imageName, purl)
			default:
				Expect(properties).To(ContainElement(negative), "%s must mark %s not shipped", imageName, purl)
			}

			snapshot[imageName+"/"+purl] = yarnPnPSnapshot{Shipped: !slices.Contains(properties, negative), Occurrences: occurrences}
		}
	}

	return snapshot
}

const (
	luaBytecodeTree     = "/root/.luarocks/share/lua/5.3"
	luaBytecodeRockDir  = "/root/.luarocks/lib/luarocks/rocks-5.3/inspect/3.1.3-0"
	luaBytecodeOnlyPURL = "pkg:luarocks/inspect@3.1.3-0"
	luaBytecodeKeptPURL = "pkg:luarocks/ansicolors@1.0.2-3"
)

var luaBytecodeStrays = []string{luaBytecodeTree + "/ansicolors.lc", luaBytecodeTree + "/stray/inspect.luac"}

type luaBytecodeSnapshot struct {
	Shipped     bool
	Occurrences []cdx.EvidenceOccurrence
}

// assertLuaBytecodeOutputs proves the fixture is a valid oracle before any SBOM is read:
// the donor keeps the source of one rock only, every bytecode file has bytes of its own so
// that no digest can stand in for another path, and each importer holds exactly what it
// imported. Returns, per file of the donor's Lua tree, the occurrence it must produce.
func assertLuaBytecodeOutputs(ctx SpecContext, project *werf.Project) map[string]cdx.EvidenceOccurrence {
	repo := os.Getenv("WERF_REPO")
	Expect(repo).NotTo(BeEmpty())
	filesOf := func(imageName, dir string) map[string][]byte {
		return imageFilesUnder(pullImage(ctx, repo+"@"+stagesImageDigestOf(ctx, project, imageName)), dir)
	}

	tree := filesOf("donor", luaBytecodeTree)
	Expect(tree).NotTo(HaveKey("inspect.lua"), "the donor must keep only the bytecode of inspect")
	Expect(tree).To(HaveKey("ansicolors.lua"))
	bytecode := []string{"inspect.luac", "ansicolors.luac", "ansicolors.ljbc", "ansicolors.lc", "stray/inspect.luac"}
	for _, file := range bytecode {
		Expect(tree).To(HaveKey(file))
		Expect(string(tree[file])).To(HavePrefix("\x1bLua"), "%s must be Lua bytecode", file)
	}
	Expect(lo.Uniq(lo.Map(bytecode, func(file string, _ int) string { return digestOfString(string(tree[file])) }))).To(HaveLen(len(bytecode)))

	imported := map[string][]byte{"inspect.luac": tree["inspect.luac"]}
	Expect(filesOf("consumer", "/opt/lua")).To(Equal(imported))
	Expect(filesOf("grandchild", "/srv/lua")).To(Equal(imported))
	manifest := filesOf("donor", luaBytecodeRockDir)["rock_manifest"]
	Expect(string(manifest)).To(ContainSubstring(`"inspect.lua"`))
	Expect(filesOf("manifest-only", "/root")).To(Equal(map[string][]byte{
		strings.TrimPrefix(luaBytecodeRockDir, "/root/") + "/rock_manifest": manifest,
	}))

	return lo.MapEntries(tree, func(file string, body []byte) (string, cdx.EvidenceOccurrence) {
		return file, cdx.EvidenceOccurrence{Location: luaBytecodeTree + "/" + file, AdditionalContext: digestOfString(string(body))}
	})
}

func assertLuaBytecodeImages(ctx SpecContext, project *werf.Project, tree map[string]cdx.EvidenceOccurrence) map[string]luaBytecodeSnapshot {
	negative := cdx.Property{Name: shippedscope.PropertyShipped, Value: "false"}

	snapshot := make(map[string]luaBytecodeSnapshot)
	for _, imageName := range []string{"donor", "consumer", "grandchild", "manifest-only"} {
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{imageName}}}))

		for _, comp := range lo.FromPtr(bom.Components) {
			Expect(lo.Map(occurrencesOf(&comp), locationOf)).NotTo(ContainElement(BeElementOf(luaBytecodeStrays)),
				"%s: %s must not own bytecode under another name or directory", imageName, comp.PackageURL)
		}

		for _, purl := range []string{luaBytecodeOnlyPURL, luaBytecodeKeptPURL} {
			comp := sbomtest.FindComponentByPURL(bom, purl)
			Expect(comp).NotTo(BeNil(), "%s must retain component %s", imageName, purl)
			Expect(comp.PackageURL).To(Equal(purl))
			properties := lo.FromPtr(comp.Properties)
			occurrences := occurrencesOf(comp)

			switch {
			case imageName == "donor" && purl == luaBytecodeOnlyPURL:
				Expect(occurrences).To(ContainElement(tree["inspect.luac"]), "the compiled sibling of a deleted source must evidence %s", purl)
				Expect(properties).NotTo(ContainElement(negative), "the donor ships %s as bytecode", purl)
			case imageName == "donor":
				Expect(occurrences).To(ContainElements(tree["ansicolors.lua"], tree["ansicolors.luac"], tree["ansicolors.ljbc"]),
					"the source and its compiled siblings must evidence %s", purl)
				Expect(properties).NotTo(ContainElement(negative), "the donor ships %s", purl)
			case imageName != "manifest-only" && purl == luaBytecodeOnlyPURL:
				Expect(occurrences).To(ContainElement(tree["inspect.luac"]), "%s must keep the bytecode evidence of %s", imageName, purl)
				Expect(properties).NotTo(ContainElement(negative), "%s imported the bytecode of %s", imageName, purl)
			default:
				Expect(properties).To(ContainElement(negative), "%s must mark %s not shipped", imageName, purl)
			}

			snapshot[imageName+"/"+purl] = luaBytecodeSnapshot{Shipped: !slices.Contains(properties, negative), Occurrences: occurrences}
		}
	}

	return snapshot
}

// stand is the configuration of an increment 1 stand, read from WERF_TEST_I1_* variables.
type stand struct{ values map[string]string }

var standKeys = []string{"TRUSTED_INDEXES", "BASE", "BASE_NO_SBOM", "BASE_NO_SBOM_EMPTY", "BUILDER_NATIVE", "BUILDER_GO", "PM_PACKAGE", "PM_PACKAGE_FILE", "OTHER_INDEX"}

// requireStand skips the spec unless every variable it needs is set, and the build environment
// (pm binary, trusted indexes) of the stand is complete.
func requireStand(needs ...string) *stand {
	GinkgoHelper()
	s := &stand{values: map[string]string{}}
	var missing []string
	for _, key := range append([]string{"PM_BINARY", "PM_SHA256"}, needs...) {
		value := os.Getenv("WERF_TEST_I1_" + key)
		if value == "" {
			missing = append(missing, "WERF_TEST_I1_"+key)
		}
		s.values[key] = value
	}
	if len(missing) > 0 {
		Skip("increment 1 stand is not configured, missing " + strings.Join(missing, ", "))
	}
	for _, key := range standKeys {
		if value := os.Getenv("WERF_TEST_I1_" + key); value != "" {
			s.values[key] = value
		}
	}
	body, err := os.ReadFile(s.values["PM_BINARY"])
	Expect(err).NotTo(HaveOccurred(), "read the pm binary")
	sum := sha256.Sum256(body)
	Expect(hex.EncodeToString(sum[:])).To(Equal(s.values["PM_SHA256"]), "pm binary must match the pinned stand artifact")

	setupSbomBuildEnv()
	SuiteData.Stubs.SetEnv("WERF_SBOM_PM_BINARY", s.values["PM_BINARY"])
	SuiteData.Stubs.SetEnv("WERF_SBOM_PM_SHA256", hex.EncodeToString(sum[:]))
	SuiteData.Stubs.SetEnv("WERF_SBOM_TRUSTED_INDEXES", s.values["TRUSTED_INDEXES"])
	return s
}

func (s *stand) replace(text string) string {
	for key, value := range s.values {
		text = strings.ReplaceAll(text, "@"+key+"@", value)
	}
	return text
}

// i1Repo copies a fixture, fills its placeholders, lets prepare add files and commits the result.
func i1Repo(ctx context.Context, dirname, fixture string, s *stand, prepare func(repo string)) string {
	GinkgoHelper()
	repo := SuiteData.GetTestRepoPath(dirname)
	utils.CopyIn(utils.FixturePath(fixture), repo)
	Expect(filepath.WalkDir(repo, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Base(path) != "werf.yaml" {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(path, []byte(s.replace(string(body))), 0o644)
	})).To(Succeed())
	if prepare != nil {
		prepare(repo)
	}
	utils.RunSucceedCommand(ctx, repo, "git", "init")
	utils.RunSucceedCommand(ctx, repo, "git", "add", ".")
	utils.RunSucceedCommand(ctx, repo, "git", "commit", "-m", "initial")
	return repo
}

func writeStockELF(relPath string) func(repo string) {
	return func(repo string) {
		GinkgoHelper()
		Expect(runtime.GOOS).To(Equal("linux"), "the increment1 stand runs on Linux")
		body, err := os.ReadFile("/bin/true")
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes.HasPrefix(body, []byte("\x7fELF"))).To(BeTrue())
		Expect(os.WriteFile(filepath.Join(repo, relPath), body, 0o755)).To(Succeed())
	}
}

func hexPrefix(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:3])
}

func writeForeignELF(relPath string) func(string) {
	return func(repo string) {
		GinkgoHelper()
		record := pmreader.BuildRecord{Schema: "pm.buildinfo/v1", Artifact: "elf", Profile: pmreader.BuildProfile{ID: "c-static", Revision: "1", Platform: "linux/arm64"}, Subject: "app", Complete: true, Components: []pmreader.BuildComponent{{ID: "app", Name: "app", Version: "1", Source: pmreader.BuildSource{Kind: "declared", Locator: "dk:image:app"}}}, Inputs: []pmreader.BuildInput{}, Tools: []pmreader.BuildTool{{Name: "fixture", Version: "1", SHA256: "sha256:" + strings.Repeat("1", 64)}}}
		payload, err := json.Marshal(map[string]any{"type": "pm", "sbom": record})
		Expect(err).NotTo(HaveOccurred())
		var note bytes.Buffer
		for _, value := range []uint32{4, uint32(len(payload)), 0xcafe1a7e} {
			Expect(binary.Write(&note, binary.LittleEndian, value)).To(Succeed())
		}
		_, err = note.Write(append([]byte("FDO\x00"), payload...))
		Expect(err).NotTo(HaveOccurred())
		for note.Len()%4 != 0 {
			Expect(note.WriteByte(0)).To(Succeed())
		}
		names := []byte("\x00.shstrtab\x00.note.package\x00")
		header := elf.Header64{Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_AARCH64), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Shentsize: 64, Shnum: 3, Shstrndx: 1, Shoff: uint64(64 + note.Len() + len(names))}
		var body bytes.Buffer
		for _, value := range []any{header, note.Bytes(), names, elf.Section64{}, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(64 + note.Len()), Size: uint64(len(names)), Addralign: 1}, elf.Section64{Name: 11, Type: uint32(elf.SHT_NOTE), Off: 64, Size: uint64(note.Len()), Addralign: 4}} {
			Expect(binary.Write(&body, binary.LittleEndian, value)).To(Succeed())
		}
		info, err := pmreader.ReadBuildInfo(bytes.NewReader(body.Bytes()))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Status).To(Equal("present"))
		Expect(os.WriteFile(filepath.Join(repo, relPath), body.Bytes(), 0o755)).To(Succeed())
	}
}
