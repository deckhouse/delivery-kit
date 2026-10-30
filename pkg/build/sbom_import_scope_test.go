package build

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http/httptest"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
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
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
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

// describingNoFiles is how a source says of one of its components that it describes no
// files of the image - a tool it was built with, an environment it was built in.
func describingNoFiles(comp cdx.Component) cdx.Component {
	comp.Properties = &[]cdx.Property{{Name: shippedscope.PropertyFiles, Value: shippedscope.PropertyFilesNone}}

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
			describingNoFiles(occurring("builder-toolchain", "3.0")),
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

	// A component the source says nothing of the whereabouts of cannot be placed by a
	// partial import: dropping it would quietly narrow what the importing image is said
	// to be made of, and keeping it would claim files nothing ties to this image.
	It("reads no data out of a component the source places nowhere", func(specCtx SpecContext) {
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{occurring("libfoo", "1.2.3")}

		_, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).To(MatchError(ContainSubstring("no-data: the source states no whereabouts of libfoo 1.2.3 (libfoo), so a partial import of it places nothing")))
	})

	// An import of the whole image leaves no part of the source it could have belonged
	// to instead.
	DescribeTable("keeps a component placed nowhere when the import takes the source entire",
		func(specCtx SpecContext, directive nativegate.ImportScope, kept bool) {
			bom := cyclonedxutil.NewBOM()
			bom.Components = &[]cdx.Component{occurring("libfoo", "1.2.3")}

			scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{directive})
			if !kept {
				Expect(err).To(MatchError(ContainSubstring("no-data")))

				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(componentNames(scoped)).To(ConsistOf("libfoo"))
		},
		Entry("the whole rootfs", nativegate.ImportScope{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/"}, true),
		Entry("the whole rootfs under another prefix", nativegate.ImportScope{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/srv"}, true),
		Entry("the rootfs with something filtered out of it", nativegate.ImportScope{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/", ExcludePaths: []string{"var"}}, false),
		Entry("the rootfs with only a part of it included", nativegate.ImportScope{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/", IncludePaths: []string{"usr"}}, false),
		Entry("a subtree of the source", nativegate.ImportScope{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/usr", ToPath: "/usr"}, false),
		// The other backend keeps applying filters inside what it copies, so the
		// directive alone does not settle that it took everything.
		Entry("the rootfs copied by rsync", nativegate.ImportScope{Backend: nativegate.ImportBackendRsync, FromPath: "/", ToPath: "/"}, false),
	)

	// What the source says it does not ship, it does not ship however much of it was
	// copied.
	It("drops a component the source says ships nothing even when the import takes the source entire", func(specCtx SpecContext) {
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{describingNoFiles(occurring("builder-toolchain", "3.0"))}

		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom,
			[]nativegate.ImportScope{{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(scoped.Components).To(BeNil())
	})

	It("reads the root of the source however the directive spells it", func(specCtx SpecContext) {
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{occurring("libfoo", "1.2.3")}

		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom,
			[]nativegate.ImportScope{{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/.", ToPath: "/srv"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("libfoo"))
	})

	// A heading the donor hangs other components off says nothing of itself; once the
	// import carries none of what it held, there is nothing left of it to place.
	It("drops a holder of components the import carries none of", func(specCtx SpecContext) {
		holder := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "node_modules", BOMRef: "node_modules"}
		holder.Components = &[]cdx.Component{occurring("left-behind", "1.0", "/srv/left.js")}
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{holder}

		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(scoped.Components).To(BeNil())
	})

	// A holder that names a package of its own is a claim about the image like any
	// other, and losing its children is no answer for it.
	DescribeTable("reads no data out of a holder that names a package of its own",
		func(specCtx SpecContext, identify func(*cdx.Component)) {
			holder := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "bundle", BOMRef: "bundle"}
			identify(&holder)
			holder.Components = &[]cdx.Component{occurring("left-behind", "1.0", "/srv/left.js")}
			bom := cyclonedxutil.NewBOM()
			bom.Components = &[]cdx.Component{holder}

			_, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

			Expect(err).To(MatchError(ContainSubstring("no-data: the source states no whereabouts of bundle")))
		},
		Entry("by its purl", func(comp *cdx.Component) { comp.PackageURL = "pkg:npm/bundle@1.0" }),
		Entry("by its version", func(comp *cdx.Component) { comp.Version = "1.0" }),
		Entry("by its CPE", func(comp *cdx.Component) { comp.CPE = "cpe:2.3:a:vendor:bundle:1.0:*:*:*:*:*:*:*" }),
	)

	DescribeTable("drops a component the source says describes no files of the image",
		func(specCtx SpecContext, comp cdx.Component) {
			bom := cyclonedxutil.NewBOM()
			bom.Components = &[]cdx.Component{comp}

			scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

			Expect(err).NotTo(HaveOccurred())
			Expect(scoped.Components).To(BeNil())
		},
		Entry("marked as describing no files", describingNoFiles(occurring("builder-toolchain", "3.0"))),
		Entry("marked as not shipped by the image", func() cdx.Component {
			comp := occurring("builder-toolchain", "3.0")
			comp.Properties = &[]cdx.Property{{Name: shippedscope.PropertyShipped, Value: shippedscope.PropertyShippedFalse}}

			return comp
		}()),
		Entry("scoped out of the document", func() cdx.Component {
			comp := occurring("builder-toolchain", "3.0")
			comp.Scope = cdx.ScopeExcluded

			return comp
		}()),
	)

	// "unknown" says the opposite of "none": the source could not tell what this
	// component ships, which is not a statement that it ships nothing.
	It("reads no data out of a component whose file evidence the source calls unknown", func(specCtx SpecContext) {
		comp := occurring("libfoo", "1.2.3")
		comp.Properties = &[]cdx.Property{{Name: shippedscope.PropertyFiles, Value: "unknown"}}
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{comp}

		_, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).To(MatchError(ContainSubstring("no-data: the source states no whereabouts of libfoo 1.2.3")))
	})

	// What this project verifies is written with the whereabouts of everything in it -
	// a file component at the file it is, a package at every file of it the image holds
	// (asserted of the gate itself in pkg/sbom/nativegate) - so a document of ours is
	// placed by a partial import rather than refused by the rule above.
	It("keeps the components of a document shaped as this project verifies them", func(specCtx SpecContext) {
		fileRef := "sha256:" + strings.Repeat("a", 64) + ":/app/bin/tool"
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{
			{
				Type: cdx.ComponentTypeFile, BOMRef: fileRef, Name: "/app/bin/tool",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
					{Location: "/app/bin/tool", AdditionalContext: "sha256:" + strings.Repeat("a", 64)},
				}},
			},
			{
				Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:generic/example@1", Name: "example", Version: "1",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
					{Location: "/app/bin/tool", AdditionalContext: "sha256:" + strings.Repeat("a", 64)},
					{Location: "/srv/elsewhere", AdditionalContext: "sha256:" + strings.Repeat("b", 64)},
				}},
			},
		}

		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("/app/bin/tool", "example"))
	})

	// A package a supplier's SBOM names arrives stating nowhere it stands; strict
	// convergence places it from the image's own dpkg database, and a partial import of
	// that image then keeps what it carried and leaves the rest behind.
	It("places the inherited packages of a source so that a partial import can scope them", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		carried := cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: "carried", Name: "libfoo", Version: "1.0",
			PackageURL: "pkg:deb/debian/libfoo@1.0?arch=amd64",
		}
		leftBehind := cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: "left-behind", Name: "libbar", Version: "2.0",
			PackageURL: "pkg:deb/debian/libbar@2.0?arch=amd64",
		}
		supplied := cyclonedxutil.NewBOM()
		supplied.Components = &[]cdx.Component{carried, leftBehind}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		database, err := shippedscope.DistroPackages(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		// Before: the source states no whereabouts of either, and a partial import of
		// it can place neither.
		_, err = scopeImportBOM(ctx, supplied, []nativegate.ImportScope{scope()})
		Expect(err).To(MatchError(ContainSubstring("no-data: the source states no whereabouts of")))

		placed, _ := shippedscope.PlaceInheritedPackages(ctx, supplied, database)
		Expect(placed).To(Equal(2))

		scoped, err := scopeImportBOM(ctx, supplied, []nativegate.ImportScope{scope()})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("libfoo"), "the import carries the files of one of them and none of the other")
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

// inheritedPackageImage is an image whose dpkg database records two packages: one whose
// files sit under the path the import directives of these specs carry, one whose do not.
func inheritedPackageImage() (v1.Image, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	files := map[string]string{
		"var/lib/dpkg/status": "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n" +
			"Package: libbar\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.0\n",
		"var/lib/dpkg/info/libfoo.list": "/app/lib/libfoo.so\n",
		"var/lib/dpkg/info/libbar.list": "/srv/lib/libbar.so\n",
		"app/lib/libfoo.so":             "foo",
		"srv/lib/libbar.so":             "bar",
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name]))}); err != nil {
			return nil, err
		}
		if _, err := writer.Write([]byte(files[name])); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	layer, err := fixtureLayer(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return mutate.AppendLayers(empty.Image, layer)
}
