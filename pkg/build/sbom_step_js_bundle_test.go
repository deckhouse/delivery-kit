package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("JavaScript bundle evidence in the image SBOM", func() {
	digestOf := func(body string) string {
		sum := sha256.Sum256([]byte(body))

		return "sha256:" + hex.EncodeToString(sum[:])
	}

	imageWithFiles := func(files map[string]string) v1.Image {
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		for _, path := range lo.Keys(files) {
			Expect(writer.WriteHeader(&tar.Header{
				Name:     strings.TrimPrefix(path, "/"),
				Typeflag: tar.TypeReg,
				Size:     int64(len(files[path])),
				Mode:     0o644,
			})).To(Succeed())
			_, err := io.WriteString(writer, files[path])
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(writer.Close()).To(Succeed())

		img, err := mutate.AppendLayers(empty.Image, static.NewLayer(buf.Bytes(), types.DockerUncompressedLayer))
		Expect(err).NotTo(HaveOccurred())

		return img
	}

	backendWithFiles := func(files map[string]string) *savedImageBackend {
		img := imageWithFiles(files)
		tag, err := name.NewTag("werf-stages:app")
		Expect(err).NotTo(HaveOccurred())
		var saved bytes.Buffer
		Expect(tarball.Write(tag, img, &saved)).To(Succeed())

		return &savedImageBackend{tarball: saved.Bytes()}
	}

	logOf := func(outputs ...jsobserver.Output) string {
		data, err := json.Marshal(jsobserver.Event{Version: jsobserver.ProtocolVersion, Outputs: outputs})
		Expect(err).NotTo(HaveOccurred())

		return string(data) + "\n"
	}

	byPURL := func(bom *cdx.BOM, purl string) cdx.Component {
		comp, found := lo.Find(lo.FromPtr(bom.Components), func(comp cdx.Component) bool { return comp.PackageURL == purl })
		Expect(found).To(BeTrue(), purl)

		return comp
	}

	notShipped := cdx.Property{Name: "werf:shipped", Value: "false"}

	BeforeEach(func() {
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
	})

	It("adds a pruned bundled package, proves it in the image and in an image importing the bundle", func(ctx SpecContext) {
		backend := backendWithFiles(map[string]string{
			"/app/dist/main.js":                     "main chunk",
			"/app/dist/changed.js":                  "minified after bundling",
			"/app/node_modules/listed/package.json": `{"name":"listed","version":"1.0.0"}`,
			jsobserver.LogPath: logOf(
				jsobserver.Output{Path: "/app/dist/main.js", Digest: digestOf("main chunk"), Packages: []jsobserver.Package{
					{Name: "@scope/pruned", Version: "2.0.0"},
					{Name: "listed", Version: "1.0.0"},
				}},
				jsobserver.Output{Path: "/app/dist/changed.js", Digest: digestOf("as bundled"), Packages: []jsobserver.Package{
					{Name: "clouded", Version: "1.0.0"},
				}},
			),
		})
		target := cyclonedxutil.NewBOM()
		target.Components = &[]cdx.Component{
			{BOMRef: "listed", Name: "listed", Version: "1.0.0", PackageURL: "pkg:npm/listed@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/listed/index.js", AdditionalContext: digestOf("listed")},
			}}},
			{BOMRef: "clouded", Name: "clouded", Version: "1.0.0", PackageURL: "pkg:npm/clouded@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/clouded/index.js", AdditionalContext: digestOf("clouded")},
			}}},
			{BOMRef: "shaken", Name: "shaken", Version: "1.0.0", PackageURL: "pkg:npm/shaken@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/shaken/index.js", AdditionalContext: digestOf("shaken")},
			}}},
		}

		filesets, produced := collectShippedScope(ctx, backend, "app", "werf-stages:app", sbomStageProvenance{})
		Expect(filesets).NotTo(BeNil())
		pruned := bundleComponentsBOM(ctx, filesets, []*cdx.BOM{target, nil})
		Expect(pruned).NotTo(BeNil())
		merged, err := cyclonedxutil.MergeBOMs(ctx, target, cyclonedxutil.MergeOpts{ImportBOMs: []*cdx.BOM{pruned}})
		Expect(err).NotTo(HaveOccurred())
		recordShippedScope(ctx, merged, filesets, produced, "app")

		data, err := cyclonedxutil.ToJSON(merged)
		Expect(err).NotTo(HaveOccurred())
		Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(Succeed())
		donor, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		Expect(err).NotTo(HaveOccurred())

		bundled := cdx.EvidenceOccurrence{Location: "/app/dist/main.js", AdditionalContext: "werf:js-bundle:v1:" + digestOf("main chunk")}
		prunedComp := byPURL(donor, "pkg:npm/%40scope/pruned@2.0.0")
		Expect(prunedComp.Name).To(Equal("@scope/pruned"))
		Expect(prunedComp.Version).To(Equal("2.0.0"))
		Expect(prunedComp.Licenses).To(BeNil(), "nothing is invented about a package only a bundle names")
		Expect(prunedComp.Evidence).NotTo(BeNil())
		Expect(lo.FromPtr(prunedComp.Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{bundled}))
		Expect(lo.FromPtr(prunedComp.Properties)).NotTo(ContainElement(notShipped))
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/listed@1.0.0").Properties)).NotTo(ContainElement(notShipped))
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/clouded@1.0.0").Properties)).To(ConsistOf(cdx.Property{Name: "werf:js-bundles", Value: "unknown"}))
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/shaken@1.0.0").Properties)).To(ContainElement(notShipped))
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/clouded@1.0.0").Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/app/node_modules/clouded/index.js", AdditionalContext: digestOf("clouded")},
		}), "an output that changed proves nothing")

		importer := backendWithFiles(map[string]string{"/srv/www/main.js": "main chunk"})
		importerFilesets, importerProduced := collectShippedScope(ctx, importer, "web", "werf-stages:app", sbomStageProvenance{})
		Expect(bundleComponentsBOM(ctx, importerFilesets, []*cdx.BOM{donor})).To(BeNil())
		recordShippedScope(ctx, donor, importerFilesets, importerProduced, "web")

		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/%40scope/pruned@2.0.0").Properties)).NotTo(ContainElement(notShipped))
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/listed@1.0.0").Properties)).NotTo(ContainElement(notShipped),
			"the bundle the importer moved still holds the package its installed files left behind")
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/clouded@1.0.0").Properties)).NotTo(ContainElement(notShipped))
		Expect(lo.FromPtr(byPURL(donor, "pkg:npm/%40scope/pruned@2.0.0").Evidence.Occurrences)).To(ContainElement(bundled),
			"the donor's record of where the bundle was is kept")
	})

	It("adds nothing and changes nothing when the build left no log", func(ctx SpecContext) {
		backend := backendWithFiles(map[string]string{"/app/dist/main.js": "main chunk"})
		target := cyclonedxutil.NewBOM()
		target.Components = &[]cdx.Component{
			{BOMRef: "shaken", Name: "shaken", Version: "1.0.0", PackageURL: "pkg:npm/shaken@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/shaken/index.js", AdditionalContext: digestOf("shaken")},
			}}},
		}

		filesets, produced := collectShippedScope(ctx, backend, "app", "werf-stages:app", sbomStageProvenance{})
		Expect(bundleComponentsBOM(ctx, filesets, []*cdx.BOM{target})).To(BeNil())
		recordShippedScope(ctx, target, filesets, produced, "app")

		Expect(lo.FromPtr((*target.Components)[0].Properties)).To(Equal([]cdx.Property{notShipped}))
		Expect(lo.FromPtr((*target.Components)[0].Evidence.Occurrences)).To(HaveLen(1))
	})

	It("records a pruned bundled package in the SBOM a stapel image converges to, after the build moved its bundle", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server := httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		repo := strings.TrimPrefix(server.URL, "http://") + "/bundles"
		ref, err := name.NewTag(repo + ":app")
		Expect(err).NotTo(HaveOccurred())

		img := imageWithFiles(map[string]string{
			"/srv/www/main.js": "main chunk",
			jsobserver.LogPath: logOf(jsobserver.Output{Path: "/app/dist/main.js", Digest: digestOf("main chunk"), Packages: []jsobserver.Package{
				{Name: "pruned", Version: "1.0.0"},
			}}),
		})
		Expect(remote.Write(ref, img, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
		digest, err := img.Digest()
		Expect(err).NotTo(HaveOccurred())
		var saved bytes.Buffer
		Expect(tarball.Write(ref, img, &saved)).To(Succeed())
		info := &image.Info{Name: ref.Name(), Repository: repo, RepoDigest: repo + "@" + digest.String()}
		desc := &image.StageDesc{StageID: image.NewStageID("bundles", 1), Info: info}

		ctrl := gomock.NewController(GinkgoT())
		backend := mock.NewMockContainerBackend(ctrl)
		backend.EXPECT().Pull(gomock.Any(), info.Name, gomock.Any()).Return(nil).Times(1)
		backend.EXPECT().SaveImageToStream(gomock.Any(), info.Name).Return(io.NopCloser(bytes.NewReader(saved.Bytes())), nil).Times(1)
		var resolved []string
		externalRefPatcher := mock.NewMockBOMPatcher(ctrl)
		externalRefPatcher.EXPECT().Apply(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
			resolved = lo.Map(lo.FromPtr(bom.Components), func(comp cdx.Component, _ int) string { return comp.PackageURL })
			return bom, nil
		}).Times(1)

		step := &sbomStep{containerBackend: backend}
		Expect(step.ConvergeWithMerge(ctx, "app", desc, scanner.DefaultSyftScanOptions(), cyclonedxutil.MergeOpts{}, []BOMPatcherInterface{}, externalRefPatcher, []string{}, true, "", nil, "")).To(Succeed())

		Expect(resolved).To(ContainElement("pkg:npm/pruned@1.0.0"), "the added package has its external references resolved like any other")
		bom, err := step.GetImageBOM(ctx, "app", info)
		Expect(err).NotTo(HaveOccurred())
		comp := byPURL(bom, "pkg:npm/pruned@1.0.0")
		Expect(lo.FromPtr(comp.Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/app/dist/main.js", AdditionalContext: "werf:js-bundle:v1:" + digestOf("main chunk")},
		}))
		Expect(lo.FromPtr(comp.Properties)).NotTo(ContainElement(notShipped))
	})
})
