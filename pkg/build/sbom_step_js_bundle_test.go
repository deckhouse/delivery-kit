package build

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
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

var _ = ginkgo.Describe("JavaScript bundle evidence in the image SBOM", func() {
	notShipped := cdx.Property{Name: "werf:shipped", Value: "false"}

	ginkgo.BeforeEach(func() {
		gomega.Expect(werf.Init(ginkgo.GinkgoT().TempDir(), "")).To(gomega.Succeed())
	})

	ginkgo.It("adds a pruned bundled package, proves it in the image and in an image importing the bundle", func(ctx ginkgo.SpecContext) {
		backend := savedImageBackendWithFiles(map[string]string{
			"/app/dist/main.js":                     "main chunk",
			"/app/dist/changed.js":                  "minified after bundling",
			"/app/node_modules/listed/package.json": `{"name":"listed","version":"1.0.0"}`,
			jsobserver.LogPath: jsObserverLogOf(
				jsobserver.Output{Path: "/app/dist/main.js", Digest: sha256DigestOf("main chunk"), Packages: []jsobserver.Package{
					{Name: "@scope/pruned", Version: "2.0.0"},
					{Name: "listed", Version: "1.0.0"},
				}},
				jsobserver.Output{Path: "/app/dist/changed.js", Digest: sha256DigestOf("as bundled"), Packages: []jsobserver.Package{
					{Name: "clouded", Version: "1.0.0"},
				}},
			),
		})
		target := cyclonedxutil.NewBOM()
		target.Components = &[]cdx.Component{
			{BOMRef: "listed", Name: "listed", Version: "1.0.0", PackageURL: "pkg:npm/listed@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/listed/index.js", AdditionalContext: sha256DigestOf("listed")},
			}}},
			{BOMRef: "clouded", Name: "clouded", Version: "1.0.0", PackageURL: "pkg:npm/clouded@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/clouded/index.js", AdditionalContext: sha256DigestOf("clouded")},
			}}},
			{BOMRef: "shaken", Name: "shaken", Version: "1.0.0", PackageURL: "pkg:npm/shaken@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/shaken/index.js", AdditionalContext: sha256DigestOf("shaken")},
			}}},
		}

		filesets, produced := collectShippedScope(ctx, backend, "app", "werf-stages:app", sbomStageProvenance{})
		gomega.Expect(filesets).NotTo(gomega.BeNil())
		pruned := bundleComponentsBOM(ctx, filesets, []*cdx.BOM{target, nil})
		gomega.Expect(pruned).NotTo(gomega.BeNil())
		merged, err := cyclonedxutil.MergeBOMs(ctx, target, cyclonedxutil.MergeOpts{ImportBOMs: []*cdx.BOM{pruned}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		recordShippedScope(ctx, merged, filesets, produced, "app")

		data, err := cyclonedxutil.ToJSON(merged)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(gomega.Succeed())
		donor, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		bundled := cdx.EvidenceOccurrence{Location: "/app/dist/main.js", AdditionalContext: "werf:js-bundle:v1:" + sha256DigestOf("main chunk")}
		prunedComp := componentByPURL(donor, "pkg:npm/%40scope/pruned@2.0.0")
		gomega.Expect(prunedComp.Name).To(gomega.Equal("@scope/pruned"))
		gomega.Expect(prunedComp.Version).To(gomega.Equal("2.0.0"))
		gomega.Expect(prunedComp.Licenses).To(gomega.BeNil(), "nothing is invented about a package only a bundle names")
		gomega.Expect(prunedComp.Evidence).NotTo(gomega.BeNil())
		gomega.Expect(lo.FromPtr(prunedComp.Evidence.Occurrences)).To(gomega.Equal([]cdx.EvidenceOccurrence{bundled}))
		gomega.Expect(lo.FromPtr(prunedComp.Properties)).NotTo(gomega.ContainElement(notShipped))
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/listed@1.0.0").Properties)).NotTo(gomega.ContainElement(notShipped))
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/clouded@1.0.0").Properties)).To(gomega.ConsistOf(cdx.Property{Name: "werf:js-bundles", Value: "unknown"}))
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/shaken@1.0.0").Properties)).To(gomega.ContainElement(notShipped))
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/clouded@1.0.0").Evidence.Occurrences)).To(gomega.Equal([]cdx.EvidenceOccurrence{
			{Location: "/app/node_modules/clouded/index.js", AdditionalContext: sha256DigestOf("clouded")},
		}), "an output that changed proves nothing")

		importer := savedImageBackendWithFiles(map[string]string{"/srv/www/main.js": "main chunk"})
		importerFilesets, importerProduced := collectShippedScope(ctx, importer, "web", "werf-stages:app", sbomStageProvenance{})
		gomega.Expect(bundleComponentsBOM(ctx, importerFilesets, []*cdx.BOM{donor})).To(gomega.BeNil())
		recordShippedScope(ctx, donor, importerFilesets, importerProduced, "web")

		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/%40scope/pruned@2.0.0").Properties)).NotTo(gomega.ContainElement(notShipped))
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/listed@1.0.0").Properties)).NotTo(gomega.ContainElement(notShipped),
			"the bundle the importer moved still holds the package its installed files left behind")
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/clouded@1.0.0").Properties)).NotTo(gomega.ContainElement(notShipped))
		gomega.Expect(lo.FromPtr(componentByPURL(donor, "pkg:npm/%40scope/pruned@2.0.0").Evidence.Occurrences)).To(gomega.ContainElement(bundled),
			"the donor's record of where the bundle was is kept")
	})

	ginkgo.It("adds nothing and changes nothing when the build left no log", func(ctx ginkgo.SpecContext) {
		backend := savedImageBackendWithFiles(map[string]string{"/app/dist/main.js": "main chunk"})
		target := cyclonedxutil.NewBOM()
		target.Components = &[]cdx.Component{
			{BOMRef: "shaken", Name: "shaken", Version: "1.0.0", PackageURL: "pkg:npm/shaken@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/app/node_modules/shaken/index.js", AdditionalContext: sha256DigestOf("shaken")},
			}}},
		}

		filesets, produced := collectShippedScope(ctx, backend, "app", "werf-stages:app", sbomStageProvenance{})
		gomega.Expect(bundleComponentsBOM(ctx, filesets, []*cdx.BOM{target})).To(gomega.BeNil())
		recordShippedScope(ctx, target, filesets, produced, "app")

		gomega.Expect(lo.FromPtr((*target.Components)[0].Properties)).To(gomega.Equal([]cdx.Property{notShipped}))
		gomega.Expect(lo.FromPtr((*target.Components)[0].Evidence.Occurrences)).To(gomega.HaveLen(1))
	})

	ginkgo.It("records a pruned bundled package in the SBOM a stapel image converges to, after the build moved its bundle", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		gomega.Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(gomega.Succeed())
		server := httptest.NewServer(registry.New())
		ginkgo.DeferCleanup(server.Close)
		repo := strings.TrimPrefix(server.URL, "http://") + "/bundles"
		ref, err := name.NewTag(repo + ":app")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		img := imageWithFiles(map[string]string{
			"/srv/www/main.js": "main chunk",
			jsobserver.LogPath: jsObserverLogOf(jsobserver.Output{Path: "/app/dist/main.js", Digest: sha256DigestOf("main chunk"), Packages: []jsobserver.Package{
				{Name: "pruned", Version: "1.0.0"},
			}}),
		})
		gomega.Expect(remote.Write(ref, img, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(gomega.Succeed())
		digest, err := img.Digest()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var saved bytes.Buffer
		gomega.Expect(tarball.Write(ref, img, &saved)).To(gomega.Succeed())
		info := &image.Info{Name: ref.Name(), Repository: repo, RepoDigest: repo + "@" + digest.String()}
		desc := &image.StageDesc{StageID: image.NewStageID("bundles", 1), Info: info}

		ctrl := gomock.NewController(ginkgo.GinkgoT())
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
		gomega.Expect(step.ConvergeWithMerge(ctx, "app", desc, scanner.DefaultSyftScanOptions(), cyclonedxutil.MergeOpts{}, []BOMPatcherInterface{}, externalRefPatcher, []string{}, true, "", nil, "")).To(gomega.Succeed())

		gomega.Expect(resolved).To(gomega.ContainElement("pkg:npm/pruned@1.0.0"), "the added package has its external references resolved like any other")
		bom, err := step.GetImageBOM(ctx, "app", info)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		comp := componentByPURL(bom, "pkg:npm/pruned@1.0.0")
		gomega.Expect(lo.FromPtr(comp.Evidence.Occurrences)).To(gomega.Equal([]cdx.EvidenceOccurrence{
			{Location: "/app/dist/main.js", AdditionalContext: "werf:js-bundle:v1:" + sha256DigestOf("main chunk")},
		}))
		gomega.Expect(lo.FromPtr(comp.Properties)).NotTo(gomega.ContainElement(notShipped))
	})
})
