package build

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

// occurring builds a component of a donor's SBOM that the donor says it holds at the
// given paths. A component named with no path at all is one the donor states nothing
// about the whereabouts of.
func occurring(name, version string, paths ...string) cdx.Component {
	comp := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: name, Version: version, BOMRef: name}
	if len(paths) == 0 {
		return comp
	}
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(paths))
	for _, path := range paths {
		occurrences = append(occurrences, cdx.EvidenceOccurrence{Location: path})
	}
	comp.Evidence = &cdx.Evidence{Occurrences: &occurrences}

	return comp
}

func componentNames(bom *cdx.BOM) []string {
	var names []string
	if bom == nil || bom.Components == nil {
		return names
	}
	for _, comp := range *bom.Components {
		names = append(names, comp.Name)
	}

	return names
}

var _ = Describe("SBOM contributions of an import source", func() {
	const targetPlatform = "linux/amd64"

	// An import source image holding one imported file, whose SBOM also describes the
	// environment the donor built in: a component of a file the import leaves behind,
	// and a tool component the donor states no whereabouts of at all.
	contributed := func(ctx context.Context, components []cdx.Component, imports []*config.Import, bootstrap ...string) []*cdx.BOM {
		GinkgoHelper()
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server := httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		registryHost := strings.TrimPrefix(server.URL, "http://")

		sourceRepo := registryHost + "/builder"
		sourceRef, err := name.NewTag(sourceRepo + ":latest")
		Expect(err).NotTo(HaveOccurred())
		sourceImg := sourceSnapshotImage([]sourceSnapshotFile{
			{Name: "app/bin/tool", Body: "tool"},
			{Name: "src/app.py", Body: "print(1)"},
		})
		Expect(remote.Write(sourceRef, sourceImg, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
		sourceDigest, err := sourceImg.Digest()
		Expect(err).NotTo(HaveOccurred())

		sourceBOM := cyclonedxutil.NewBOM()
		sourceBOM.Components = &components
		sourceJSON, err := cyclonedxutil.ToJSON(sourceBOM)
		Expect(err).NotTo(HaveOccurred())
		Expect(sbomImage.PushSBOM(ctx, sourceJSON, sourceRepo, sourceDigest.String(), "", "checksum", "", nil)).To(Succeed())

		infos := map[string]*imagePkg.Info{
			sourceRepo + ":latest": {Name: sourceRepo + ":latest", Repository: sourceRepo, RepoDigest: sourceRepo + "@" + sourceDigest.String()},
		}
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
		backend.EXPECT().
			GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ any, ref string, _ container_backend.GetImageInfoOpts) (*imagePkg.Info, error) {
				return infos[ref], nil
			}).AnyTimes()

		for _, directive := range imports {
			directive.From = sourceRepo + ":latest"
		}
		tree := buildImage.NewImagesTree(nil, buildImage.ImagesTreeOptions{})
		// A source of this very recipe, declaring itself a bootstrap image, imported
		// by name rather than as an image from somewhere else.
		for _, name := range bootstrap {
			for _, directive := range imports {
				directive.From = name
				directive.ExternalImage = false
			}
			infos[name] = infos[sourceRepo+":latest"]
			source := &buildImage.Image{Name: name, TargetPlatform: targetPlatform}
			source.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{
				Name:      name,
				ImageSpec: &config.ImageSpec{Labels: map[string]string{sbomBuildContextLabel: `{"version":1,"bootstrap":true}`}},
			}}
			tree.AppendImageForTests(source)
		}
		img := &buildImage.Image{TargetPlatform: targetPlatform}
		baseConfig := &config.StapelImageBase{Import: imports}
		stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: targetPlatform}
		img.SetStages(recordingImportBackend("copy-recurse", stage.GenerateDependenciesBeforeInstallStage(baseConfig, stageOpts)))

		phase := &BuildPhase{
			BasePhase: BasePhase{Conveyor: &Conveyor{ContainerBackend: backend, imagesTree: tree}},
			sbomStep:  newSbomStep(backend, nil),
		}
		boms, _, err := phase.collectImportImageSboms(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		return boms
	}

	scoped := func(add, to string, include, exclude []string) *config.Import {
		return &config.Import{
			Export:        &config.Export{ExportBase: &config.ExportBase{Add: add, To: to, IncludePaths: include, ExcludePaths: exclude}},
			Before:        string(stage.Install),
			ExternalImage: true,
		}
	}

	// A bootstrap image is built to be imported from and never shipped: this project
	// claims nothing about its composition, so nothing it says about itself is read.
	It("reads nothing of a source the recipe declares a bootstrap image", func(specCtx SpecContext) {
		boms := contributed(logging.WithLogger(specCtx), []cdx.Component{
			occurring("tool", "1.0", "/app/bin/tool"),
		}, []*config.Import{scoped("/app/bin", "/usr/local/bin", nil, nil)}, "builder")

		Expect(boms).To(BeEmpty(), "the SBOM of a bootstrap source is neither read nor merged")
	})

	// Nothing of a bootstrap image's own composition is converged: an image with no
	// stage descriptor at all is one every other path of this convergence refuses, and
	// a bootstrap image is let go before any of it is read.
	It("converges no document for a bootstrap image", func(specCtx SpecContext) {
		img := &buildImage.Image{TargetPlatform: targetPlatform}
		img.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			Name:      "builder",
			ImageSpec: &config.ImageSpec{Labels: map[string]string{sbomBuildContextLabel: `{"version":1,"bootstrap":true}`}},
		}}
		phase := &BuildPhase{}

		Expect(phase.convergePlatformImageSbom(logging.WithLogger(specCtx), "builder", img, nil, "", nil)).To(Succeed())

		ordinary := &buildImage.Image{TargetPlatform: targetPlatform}
		Expect(phase.convergePlatformImageSbom(logging.WithLogger(specCtx), "app", ordinary, nil, "", nil)).
			To(MatchError(ContainSubstring("stage descriptor is unavailable")), "any other image is read, and this one has nothing to read")
	})

	It("contributes only the components of the files the import carries", func(specCtx SpecContext) {
		boms := contributed(logging.WithLogger(specCtx), []cdx.Component{
			occurring("tool", "1.0", "/app/bin/tool"),
			occurring("python-app", "2.0", "/src/app.py"),
			occurring("builder-toolchain", "3.0"),
		}, []*config.Import{scoped("/app/bin", "/usr/local/bin", nil, nil)})

		Expect(boms).To(HaveLen(1))
		Expect(componentNames(boms[0])).To(ConsistOf("tool"))
	})

	It("contributes nothing a path outside the scope is all the evidence for", func(specCtx SpecContext) {
		boms := contributed(logging.WithLogger(specCtx), []cdx.Component{
			occurring("tool", "1.0", "/app/bin/tool"),
		}, []*config.Import{scoped("/app/bin", "/usr/local/bin", []string{"other"}, nil)})

		Expect(boms).To(HaveLen(1))
		Expect(componentNames(boms[0])).To(BeEmpty(), "an include that names another file carries nothing of this one")
	})

	It("contributes a component carried by any one of several imports of the source", func(specCtx SpecContext) {
		boms := contributed(logging.WithLogger(specCtx), []cdx.Component{
			occurring("tool", "1.0", "/app/bin/tool"),
			occurring("python-app", "2.0", "/src/app.py"),
		}, []*config.Import{
			scoped("/app/bin", "/usr/local/bin", nil, nil),
			scoped("/src", "/srv", nil, []string{"app.py"}),
		})

		Expect(boms).To(HaveLen(1), "the two directives read one SBOM")
		Expect(componentNames(boms[0])).To(ConsistOf("tool"), "the second directive excludes the only file of the other component")
	})
})

var _ = Describe("Scoping one import source document", func() {
	scope := func(include ...string) nativegate.ImportScope {
		return nativegate.ImportScope{FromPath: "/app", ToPath: "/opt/app", IncludePaths: include}
	}

	It("keeps a holder of components for whatever of them the import carries", func(specCtx SpecContext) {
		held := occurring("bundled", "1.0", "/app/lib/bundled.so")
		dropped := occurring("left-behind", "1.0", "/srv/left.so")
		holder := occurring("image", "1.0")
		holder.Components = &[]cdx.Component{held, dropped}

		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{holder}
		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("image"))
		Expect(componentNames(&cdx.BOM{Components: (*scoped.Components)[0].Components})).To(ConsistOf("bundled"))
	})

	It("scopes the components the document hangs off its own subject", func(specCtx SpecContext) {
		subject := occurring("source-image", "1.0")
		subject.Components = &[]cdx.Component{
			occurring("carried", "1.0", "/app/bin/tool"),
			occurring("left-behind", "1.0", "/srv/other"),
		}

		bom := cyclonedxutil.NewBOM()
		bom.Metadata = &cdx.Metadata{Component: &subject}
		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(&cdx.BOM{Components: scoped.Metadata.Component.Components})).To(ConsistOf("carried"))
		Expect(*bom.Metadata.Component.Components).To(HaveLen(2), "the donor's own document is left as it arrived")
	})

	It("drops the edges of the components it dropped", func(specCtx SpecContext) {
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{
			occurring("carried", "1.0", "/app/bin/tool"),
			occurring("left-behind", "1.0", "/srv/other"),
		}
		bom.Dependencies = &[]cdx.Dependency{
			{Ref: "carried", Dependencies: &[]string{"left-behind"}},
			{Ref: "left-behind", Dependencies: &[]string{"carried"}},
		}
		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(*scoped.Dependencies).To(Equal([]cdx.Dependency{{Ref: "carried", Dependencies: &[]string{}}}))
	})

	// The mark that says a path came out of a bootstrap source travels in the private
	// metadata of the document, and an import of such a path must keep carrying it.
	It("keeps the private metadata the scoped document carries", func(specCtx SpecContext) {
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{occurring("carried", "1.0", "/app/bin/tool")}
		subject := occurring("source-image", "1.0")
		bom.Metadata = &cdx.Metadata{Component: &subject, Properties: &[]cdx.Property{
			{Name: "dk:bootstrap/v1", Value: `{"schema":"dk:bootstrap/v1","paths":["/app/bin/tool"]}`},
		}}
		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(*scoped.Metadata.Properties).To(Equal(*bom.Metadata.Properties))
	})

	It("reads no document for no directive at all", func(specCtx SpecContext) {
		_, err := scopeImportBOM(logging.WithLogger(specCtx), cyclonedxutil.NewBOM(), nil)
		Expect(err).To(MatchError(ContainSubstring("no-data: an import source SBOM is read for no import directive")))
	})
})

// recordingImportBackend gives a stage the built stage image it would have after the
// build, carrying the SBOM stage record that states which copy backend applied its
// imports. Nothing reads the backend of the current run any more, so a stage without
// that record is a stage whose imports cannot be scoped.
func recordingImportBackend(backend string, stages ...stage.Interface) []stage.Interface {
	GinkgoHelper()
	for _, stg := range stages {
		record, err := json.Marshal(sbomStageRecord{Stage: stg.Name(), ImportBackend: backend})
		Expect(err).NotTo(HaveOccurred())
		legacy := mock.NewMockLegacyImageInterface(gomock.NewController(GinkgoT()))
		legacy.EXPECT().GetStageDesc().Return(&imagePkg.StageDesc{Info: &imagePkg.Info{
			Labels: map[string]string{imagePkg.WerfSBOMStageLabel: string(record)},
		}}).AnyTimes()
		stg.SetStageImage(&stage.StageImage{Image: legacy})
	}

	return stages
}
