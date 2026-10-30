package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

const (
	// assetSourceName is the logical werf image the asset declaration names: a prepared
	// image of its own, not the package source the context is the subject of.
	assetSourceName  = "ui"
	assetSourceRoot  = "/ui/dist"
	assetTargetRoot  = "/build/ui/dist"
	assetProofPath   = "/.werf/assets/ui.json"
	assetUnrelated   = "/ui/meta"
	assetAppBody     = "console.log('app');\n"
	assetVendorBody  = "console.log('vendor');\n"
	assetInputBody   = "export const app = 1;\n"
	assetMetaBody    = "{\"build\":\"ui\"}\n"
	assetInputSource = "/ui/src/app.ts"
)

func assetSHA(body string) string {
	sum := sha256.Sum256([]byte(body))

	return "sha256:" + hex.EncodeToString(sum[:])
}

// assetIntegrity is the subresource integrity of bytes this fixture actually holds, not
// an integrity claimed by a package registry.
func assetIntegrity(body string) string {
	sum := sha512.Sum512([]byte(body))

	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// assetProofEntry is one delivered asset of the source proof: the bytes the collector
// shipped, and the subject-free composition that explains them.
func assetProofEntry(name, body string) map[string]any {
	return map[string]any{
		"path":   name,
		"sha256": assetSHA(body),
		"size":   len(body),
		"status": "present",
		"components": []map[string]any{{
			"id": "c0", "name": "ui-app", "version": "1",
			"source": map[string]any{
				"kind":     "node",
				"locator":  "https://registry.invalid/ui-app/-/ui-app-1.0.0.tgz",
				"checksum": assetIntegrity(assetInputBody),
			},
		}},
		"includedComponents": []string{"c0"},
		"inputs": []map[string]any{{
			"kind": "source", "path": assetInputSource, "sha256": assetSHA(assetInputBody),
			"components": []string{"c0"}, "disposition": "included",
		}},
		"tools": []map[string]any{},
	}
}

func assetProofBody(root string, version any, entries []map[string]any, drop ...string) []byte {
	ginkgo.GinkgoHelper()
	document := map[string]any{"version": version, "sourceRoot": root, "assets": entries}
	for _, member := range drop {
		delete(document, member)
	}
	data, err := json.Marshal(document)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return data
}

func defaultAssetProof() []byte {
	ginkgo.GinkgoHelper()

	return assetProofBody(assetSourceRoot, 1, []map[string]any{
		assetProofEntry("app.js", assetAppBody),
		assetProofEntry("vendor.js", assetVendorBody),
		// A row of an asset the build never got: the proof travels whole, the context
		// maps only what the import actually landed.
		assetProofEntry("legacy.js", "console.log('legacy');\n"),
	})
}

// assetCompositions checks every row of a proof against the shared composition seam the
// validator will read it with, so a delivery spec cannot pass on a fragment that is
// already invalid before any byte is verified.
func assetCompositions(proof []byte) {
	ginkgo.GinkgoHelper()
	var document struct {
		Assets []map[string]json.RawMessage `json:"assets"`
	}
	gomega.Expect(json.Unmarshal(proof, &document)).To(gomega.Succeed())
	gomega.Expect(document.Assets).NotTo(gomega.BeEmpty())
	for _, row := range document.Assets {
		fragment := make(map[string]json.RawMessage, 4)
		for _, member := range []string{"components", "includedComponents", "inputs", "tools"} {
			if raw, present := row[member]; present {
				fragment[member] = raw
			}
		}
		encoded, err := json.Marshal(fragment)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		status, err := shared.ValidateComposition(encoded, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(status).To(gomega.Equal("present"))
	}
}

// assetSourceImage layers files, symlinks and bare directories onto the configured image
// the registry fixtures use, which producerImage can only fill with regular files.
func assetSourceImage(files, symlinks map[string]string, directories ...string) v1.Image {
	ginkgo.GinkgoHelper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, directory := range directories {
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(directory, "/") + "/", Typeflag: tar.TypeDir, Mode: 0o755})).To(gomega.Succeed())
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		body := files[name]
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})).To(gomega.Succeed())
		_, err := writer.Write([]byte(body))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	for _, name := range slices.Sorted(maps.Keys(symlinks)) {
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Typeflag: tar.TypeSymlink, Mode: 0o777, Linkname: symlinks[name]})).To(gomega.Succeed())
	}
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	layer, err := fixtureLayer(buf.Bytes())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	img, err := mutate.AppendLayers(producerImage(map[string]string{}), layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return img
}

func assetBinding() map[string]any {
	return map[string]any{
		"sourceImage": assetSourceName, "sourceRoot": assetSourceRoot,
		"targetRoot": assetTargetRoot, "proofPath": assetProofPath,
	}
}

func assetDeclaration(bindings []map[string]any, consumer stage.StageName) string {
	ginkgo.GinkgoHelper()
	declared := map[string]any{
		"subject": 0,
		"packages": []map[string]any{{
			"sourceImage": producerSourceName, "packageName": producerSourceName,
			"packageVersion": "1", "packageType": "source", "sourcePlatform": producerPlatform,
		}},
	}
	if bindings != nil {
		declared["goEmbed"] = bindings
	}
	data, err := json.Marshal(map[string]any{"version": 1, "stages": map[string]any{string(consumer): declared}})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return string(data)
}

type assetFixtureOptions struct {
	// bindings is the asset intent of the declaration; nil declares the default one.
	bindings []map[string]any
	// noGoEmbed leaves the declaration without any asset intent at all.
	noGoEmbed bool
	// proofBody replaces the source proof the asset source image ships.
	proofBody []byte
	// proofAsDirectory and proofAsSymlink put something other than a file at the
	// declared proof path; omitProof leaves the path empty.
	proofAsDirectory bool
	proofAsSymlink   bool
	omitProof        bool
	// includePaths is the scope of the import that carried the asset root.
	includePaths []string
	// targetApp is what the stage actually ships at the landed asset path.
	targetApp string
	// unrelatedImport adds a second import of the same source image, of a tree the
	// declared asset root is no part of.
	unrelatedImport bool
	// laterChange ships a stage after the importing one that rewrites the landed asset,
	// and moves the context consumer behind it.
	laterChange bool
	// importBackend is what the importing stage recorded it applied the copy with.
	importBackend string
}

// assetImages is one registry holding every image an asset-carrying build reads: the
// prepared package source, the asset source with its proof, and the stage chain whose
// dependency stage actually imported the asset root.
type assetImages struct {
	pmRepo, pmRef, pmDigest string
	uiRepo, uiRef           string
	previousRef             string
	previousDesc            *imagePkg.StageDesc
	pmImage, uiImage        v1.Image
	depsImage               v1.Image
	proof                   []byte
	stopRegistry            func()
}

func buildAssetImages(ctx context.Context, opts assetFixtureOptions) *assetImages {
	ginkgo.GinkgoHelper()
	gomega.Expect(werf.Init(ginkgo.GinkgoT().TempDir(), "")).To(gomega.Succeed())
	gomega.Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")

	pmRepo := host + "/fixture/source"
	pmImage := producerImage(producerSourceLabels(), map[string]string{"/src/main.c": producerMainBody})
	pmDigest := pushProducerImage(ctx, pmRepo+":prepared", pmImage)

	proof := opts.proofBody
	if proof == nil {
		proof = defaultAssetProof()
	}
	uiFiles := map[string]string{
		assetSourceRoot + "/app.js":    assetAppBody,
		assetSourceRoot + "/vendor.js": assetVendorBody,
		assetInputSource:               assetInputBody,
		assetUnrelated + "/meta.json":  assetMetaBody,
	}
	var directories []string
	symlinks := map[string]string{}
	switch {
	case opts.omitProof:
	case opts.proofAsDirectory:
		directories = append(directories, assetProofPath)
	case opts.proofAsSymlink:
		uiFiles["/.werf/assets/real.json"] = string(proof)
		symlinks[assetProofPath] = "real.json"
	default:
		uiFiles[assetProofPath] = string(proof)
	}
	uiRepo := host + "/fixture/ui"
	uiImage := assetSourceImage(uiFiles, symlinks, directories...)
	uiDigest := pushProducerImage(ctx, uiRepo+":prepared", uiImage)

	targetApp := opts.targetApp
	if targetApp == "" {
		targetApp = assetAppBody
	}
	stagesRepo := host + "/project/stages"
	fromID := imagePkg.NewStageID(strings.Repeat("a", 56), 1)
	depsID := imagePkg.NewStageID(strings.Repeat("b", 56), 2)
	importBackend := opts.importBackend
	if importBackend == "" {
		importBackend = "copy-recurse"
	}
	base := map[string]string{"/bin/sh": "shell"}
	fromImg := producerImage(map[string]string{
		imagePkg.WerfSBOMStageLabel: producerStageRecord(stage.From, fromID.Digest, "", ""),
	}, base)
	imported := map[string]string{
		"/src/main.c":                  producerMainBody,
		assetTargetRoot + "/app.js":    targetApp,
		assetTargetRoot + "/vendor.js": assetVendorBody,
		"/build/ui/meta/meta.json":     assetMetaBody,
	}
	depsImg := producerImage(map[string]string{
		imagePkg.WerfSBOMStageLabel: producerStageRecord(stage.DependenciesBeforeInstall, depsID.Digest, fromID.String(), importBackend),
		imagePkg.WerfParentStageID:  fromID.String(),
	}, base, imported)
	pushProducerImage(ctx, stagesRepo+":"+fromID.String(), fromImg)
	depsDigest := pushProducerImage(ctx, stagesRepo+":"+depsID.String(), depsImg)
	previousID, previousImg, previousDigest := depsID, depsImg, depsDigest
	if opts.laterChange {
		// A stage built after the import rewrites what the import landed; the boundary
		// the import lands on still holds the imported bytes.
		installID := imagePkg.NewStageID(strings.Repeat("e", 56), 3)
		installImg := producerImage(map[string]string{
			imagePkg.WerfSBOMStageLabel: producerStageRecord(stage.Install, installID.Digest, depsID.String(), ""),
			imagePkg.WerfParentStageID:  depsID.String(),
		}, base, imported, map[string]string{assetTargetRoot + "/app.js": "console.log('rewritten later');\n"})
		previousID, previousImg = installID, installImg
		previousDigest = pushProducerImage(ctx, stagesRepo+":"+installID.String(), installImg)
	}
	previousRef := stagesRepo + "@" + previousDigest

	return &assetImages{
		pmRepo: pmRepo, pmRef: pmRepo + "@" + pmDigest, pmDigest: pmDigest,
		uiRepo: uiRepo, uiRef: uiRepo + "@" + uiDigest,
		previousRef: previousRef,
		previousDesc: &imagePkg.StageDesc{StageID: previousID, Info: &imagePkg.Info{
			Name: stagesRepo + ":" + previousID.String(), Repository: stagesRepo, RepoDigest: previousRef,
		}},
		pmImage: pmImage, uiImage: uiImage, depsImage: previousImg,
		proof: proof, stopRegistry: server.Close,
	}
}

type assetFixture struct {
	images *assetImages
	phase  *BuildPhase
	img    *buildImage.Image
	stg    stage.Interface
}

// wire builds the phase that is about to calculate the install stage of a build which
// imported the asset root, against images that are already in the registry.
func (images *assetImages) wire(opts assetFixtureOptions) *assetFixture {
	ginkgo.GinkgoHelper()
	backend := mock.NewMockContainerBackend(gomock.NewController(ginkgo.GinkgoT()))
	backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
	for ref, img := range map[string]v1.Image{images.previousRef: images.depsImage, images.pmRef: images.pmImage, images.uiRef: images.uiImage} {
		saved := img
		backend.EXPECT().Pull(gomock.Any(), ref, container_backend.PullOpts{TargetPlatform: producerPlatform}).Return(nil).AnyTimes()
		backend.EXPECT().SaveImageToStream(gomock.Any(), ref).
			DoAndReturn(func(_ any, _ string) (io.ReadCloser, error) { return producerImageStream(saved) }).AnyTimes()
	}

	phase := newTestBuildPhase(&recordingStorageManager{}, nil)
	phase.Conveyor.ContainerBackend = backend
	phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: true}
	phase.Conveyor.tmpDir = ginkgo.GinkgoT().TempDir()
	phase.Conveyor.giterminismManager = stage.NewGiterminismManagerStub(&producerGitRepoStub{LocalGitRepoStub: stage.NewLocalGitRepoStub("abc123")}, stage.NewGiterminismInspectorStub())
	phase.StagesIterator = NewStagesIterator(phase.Conveyor)

	for name, ref := range map[string]string{producerSourceName: images.pmRef, assetSourceName: images.uiRef} {
		repository, _, _ := strings.Cut(ref, "@")
		prepared := &buildImage.Image{Name: name, TargetPlatform: producerPlatform}
		prepared.SetContentTagDesc(&imagePkg.StageDesc{
			StageID: imagePkg.NewStageID(strings.Repeat("c", 56), 3),
			Info:    &imagePkg.Info{Name: ref, Repository: repository, RepoDigest: ref},
		})
		phase.Conveyor.imagesTree.AppendImageForTests(prepared)
	}

	bindings := opts.bindings
	if bindings == nil && !opts.noGoEmbed {
		bindings = []map[string]any{assetBinding()}
	}
	imports := []*config.Import{
		{
			Export: &config.Export{ExportBase: &config.ExportBase{Add: "/src", To: "/src", IncludePaths: []string{"main.c"}}},
			From:   producerSourceName,
			Before: string(stage.Install),
		},
		{
			Export: &config.Export{ExportBase: &config.ExportBase{Add: assetSourceRoot, To: assetTargetRoot, IncludePaths: opts.includePaths}},
			From:   assetSourceName,
			Before: string(stage.Install),
		},
	}
	if opts.unrelatedImport {
		imports = append(imports, &config.Import{
			Export: &config.Export{ExportBase: &config.ExportBase{Add: assetUnrelated, To: "/build/ui/meta"}},
			From:   assetSourceName,
			Before: string(stage.Install),
		})
	}
	consumer := stage.Install
	if opts.laterChange {
		consumer = stage.Setup
	}
	baseConfig := &config.StapelImageBase{
		Name:      "app",
		ImageSpec: &config.ImageSpec{Labels: map[string]string{stage.SBOMBuildContextLabel: assetDeclaration(bindings, consumer)}},
		Import:    imports,
	}
	stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: producerPlatform}
	depsStage := stage.GenerateDependenciesBeforeInstallStage(baseConfig, stageOpts)
	depsStage.SetStageImage(&stage.StageImage{Image: &exportLegacyImageStub{stageDesc: images.previousDesc}})
	producerStage := &producerStageStub{BaseStage: stage.NewBaseStage(consumer, stageOpts)}
	phase.StagesIterator.PrevBuiltStage = depsStage

	stages := []stage.Interface{depsStage, producerStage}
	if opts.laterChange {
		stages = []stage.Interface{depsStage, &producerStageStub{BaseStage: stage.NewBaseStage(stage.Install, stageOpts)}, producerStage}
	}
	img := &buildImage.Image{Name: "app", TargetPlatform: producerPlatform, StapelImageConfig: &config.StapelImage{StapelImageBase: baseConfig}}
	img.SetStages(stages)

	return &assetFixture{images: images, phase: phase, img: img, stg: producerStage}
}

func newAssetFixture(ctx context.Context, opts assetFixtureOptions) *assetFixture {
	ginkgo.GinkgoHelper()

	return buildAssetImages(ctx, opts).wire(opts)
}

// deliver materializes the context of the asset-carrying stage and removes its scratch
// when the spec ends.
func (fixture *assetFixture) deliver(ctx context.Context) (*sbomProducerContext, error) {
	ginkgo.GinkgoHelper()
	input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
	if input != nil {
		ginkgo.DeferCleanup(func() { gomega.Expect(os.RemoveAll(input.directory)).To(gomega.Succeed()) })
	}

	return input, err
}

// assetProofFile reads back the proof the context points the compiler at, by the path the
// private build namespace sees it at.
func assetProofFile(input *sbomProducerContext, proof buildcontext.GoEmbedProofRef) []byte {
	ginkgo.GinkgoHelper()
	gomega.Expect(proof.Path).To(gomega.HavePrefix(producerContextMount + "/"))
	body, err := os.ReadFile(filepath.Join(input.directory, strings.TrimPrefix(proof.Path, producerContextMount+"/")))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return body
}

func assetPaths(binding buildcontext.GoEmbedBinding) []string {
	paths := make([]string, 0, len(binding.Assets))
	for _, asset := range binding.Assets {
		paths = append(paths, asset.Path)
	}

	return paths
}

var _ = ginkgo.Describe("producer asset context delivery", func() {
	ginkgo.It("delivers the source proof and the assets the build actually imported", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{includePaths: []string{"app.js"}})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(input).NotTo(gomega.BeNil())

		written := producerWrittenContext(input)
		gomega.Expect(written.Subject.Name).To(gomega.Equal(producerSourceName), "the subject is still the prepared package of the stage")
		gomega.Expect(written.GoEmbed).NotTo(gomega.BeNil())
		gomega.Expect(written.GoEmbed.Validate()).To(gomega.Succeed())
		gomega.Expect(written.GoEmbed.Version).To(gomega.Equal(1))
		gomega.Expect(written.GoEmbed.Bindings).To(gomega.HaveLen(1))

		binding := written.GoEmbed.Bindings[0]
		gomega.Expect(binding.SourceStageRef).To(gomega.Equal(fixture.images.uiRef), "the binding pins the result the import copied from")
		gomega.Expect(binding.SourceRoot).To(gomega.Equal(assetSourceRoot))
		gomega.Expect(binding.TargetRoot).To(gomega.Equal(assetTargetRoot))
		gomega.Expect(binding.Assets).To(gomega.Equal([]buildcontext.GoEmbedAssetMapping{
			{SourcePath: "app.js", Path: assetTargetRoot + "/app.js"},
		}), "only the asset the import scope carried is mapped, by the path the stage holds it at")

		gomega.Expect(binding.Proof.Version).To(gomega.Equal(1))
		gomega.Expect(binding.Proof.SHA256).To(gomega.Equal(assetSHA(string(fixture.images.proof))))
		delivered := assetProofFile(input, binding.Proof)
		gomega.Expect(delivered).To(gomega.Equal(fixture.images.proof), "the proof travels as the exact bytes the source image shipped")
		assetCompositions(delivered)

		paths := make([]string, 0, len(written.Imports))
		for _, mapping := range written.Imports {
			paths = append(paths, mapping.Path)
		}
		gomega.Expect(paths).To(gomega.ConsistOf("/src/main.c"), "the asset source is no package of this context and its proof is no import of it")
	})

	ginkgo.It("maps no asset the proof names but the build never got", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{includePaths: []string{"app.js"}})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		binding := producerWrittenContext(input).GoEmbed.Bindings[0]
		gomega.Expect(assetPaths(binding)).NotTo(gomega.ContainElement(assetTargetRoot + "/vendor.js"))
		gomega.Expect(assetPaths(binding)).NotTo(gomega.ContainElement(assetTargetRoot + "/legacy.js"))
		delivered := assetProofFile(input, binding.Proof)
		gomega.Expect(string(delivered)).To(gomega.ContainSubstring("legacy.js"),
			"an unselected row stays in the proof the validator reads, it is only no mapping")
		assetCompositions(delivered)
	})

	ginkgo.It("keeps the root obligation of a binding that carried no asset at all", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{includePaths: []string{"nothing-here.js"}})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		written := producerWrittenContext(input)
		gomega.Expect(written.GoEmbed.Bindings).To(gomega.HaveLen(1), "an empty asset list does not drop the root the stage must still prove")
		gomega.Expect(written.GoEmbed.Bindings[0].Assets).To(gomega.BeEmpty())
		gomega.Expect(written.GoEmbed.Bindings[0].Proof.SHA256).NotTo(gomega.BeEmpty())
		assetCompositions(assetProofFile(input, written.GoEmbed.Bindings[0].Proof))
	})

	ginkgo.It("claims no asset whose landed bytes the stage then changed", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{targetApp: "console.log('patched');\n"})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		binding := producerWrittenContext(input).GoEmbed.Bindings[0]
		gomega.Expect(assetPaths(binding)).NotTo(gomega.ContainElement(assetTargetRoot+"/app.js"), "changed bytes are no delivered asset rather than an invented one")
		gomega.Expect(assetPaths(binding)).To(gomega.ContainElement(assetTargetRoot + "/vendor.js"))
	})

	ginkgo.It("claims no asset a later stage of the same build rewrote", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{laterChange: true, includePaths: []string{"app.js"}})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		written := producerWrittenContext(input)
		gomega.Expect(written.GoEmbed.Bindings).To(gomega.HaveLen(1), "the root obligation survives what the build did to the tree afterwards")
		gomega.Expect(written.GoEmbed.Bindings[0].Assets).To(gomega.BeEmpty(),
			"the asset the consuming stage will read is no longer the one the import landed")
	})

	ginkgo.It("reads the copy of an import by the backend the importing stage recorded", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{importBackend: "rsync"})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		binding := producerWrittenContext(input).GoEmbed.Bindings[0]
		gomega.Expect(assetPaths(binding)).To(gomega.ConsistOf(assetTargetRoot+"/app.js", assetTargetRoot+"/vendor.js"))
	})

	ginkgo.It("delivers the matching import though the same source was imported elsewhere too", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{unrelatedImport: true, includePaths: []string{"app.js"}})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "an unrelated import of the same source image is no reason to refuse the asset root")

		binding := producerWrittenContext(input).GoEmbed.Bindings[0]
		gomega.Expect(assetPaths(binding)).To(gomega.ConsistOf(assetTargetRoot + "/app.js"))
	})

	ginkgo.It("plans no asset extension for a stage that declares none", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		images := buildAssetImages(ctx, assetFixtureOptions{})

		plain, err := images.wire(assetFixtureOptions{noGoEmbed: true}).deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(producerWrittenContext(plain).GoEmbed).To(gomega.BeNil())
		gomega.Expect(filepath.Join(plain.directory, "proofs")).NotTo(gomega.BeADirectory(), "a context without asset intent materializes no proofs")

		empty, err := images.wire(assetFixtureOptions{bindings: []map[string]any{}}).deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(producerWrittenContext(empty).GoEmbed).To(gomega.BeNil(), "an explicitly empty intent is the same absent extension")
		gomega.Expect(empty.checksum).To(gomega.Equal(plain.checksum), "a build with no asset obligation keeps the checksum it had before the extension existed")
	})

	ginkgo.It("binds the stage checksum to the proof it delivered, not to the host directory", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		images := buildAssetImages(ctx, assetFixtureOptions{})
		fixture := images.wire(assetFixtureOptions{includePaths: []string{"app.js"}})

		first, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		second, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(second.directory).NotTo(gomega.Equal(first.directory))
		gomega.Expect(second.checksum).To(gomega.Equal(first.checksum), "two materializations of one plan select the same stage")

		withoutAssets, err := images.wire(assetFixtureOptions{noGoEmbed: true, includePaths: []string{"app.js"}}).deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(withoutAssets.checksum).NotTo(gomega.Equal(first.checksum), "a delivered asset obligation is part of the stage it is built for")

		// The same delivered asset bytes, a source proof that says something else about
		// them: the stage is built against another proof and cannot reuse the old one.
		changed := buildAssetImages(ctx, assetFixtureOptions{proofBody: assetProofBody(assetSourceRoot, 1, []map[string]any{
			assetProofEntry("app.js", assetAppBody), assetProofEntry("vendor.js", assetVendorBody),
		})})
		other, err := changed.wire(assetFixtureOptions{includePaths: []string{"app.js"}}).deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		otherBinding := producerWrittenContext(other).GoEmbed.Bindings[0]
		gomega.Expect(otherBinding.Assets).To(gomega.Equal(producerWrittenContext(first).GoEmbed.Bindings[0].Assets))
		gomega.Expect(otherBinding.Proof.SHA256).NotTo(gomega.Equal(producerWrittenContext(first).GoEmbed.Bindings[0].Proof.SHA256))
		gomega.Expect(other.checksum).NotTo(gomega.Equal(first.checksum))
	})

	ginkgo.It("delivers equivalent declarations of one asset root without contradicting itself", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, assetFixtureOptions{
			bindings:     []map[string]any{assetBinding(), assetBinding()},
			includePaths: []string{"app.js"},
		})

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "the same obligation declared twice is one obligation")

		written := producerWrittenContext(input)
		gomega.Expect(written.GoEmbed.Validate()).To(gomega.Succeed())
		for _, binding := range written.GoEmbed.Bindings {
			gomega.Expect(binding.TargetRoot).To(gomega.Equal(assetTargetRoot))
			gomega.Expect(binding.Proof.SHA256).To(gomega.Equal(assetSHA(string(fixture.images.proof))))
			gomega.Expect(assetPaths(binding)).To(gomega.ConsistOf(assetTargetRoot + "/app.js"))
		}
	})

	ginkgo.DescribeTable("refuses an asset delivery it cannot prove", func(specCtx ginkgo.SpecContext, opts assetFixtureOptions, expected string) {
		ctx := logging.WithLogger(specCtx)
		fixture := newAssetFixture(ctx, opts)

		input, err := fixture.deliver(ctx)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
		gomega.Expect(input).To(gomega.BeNil())

		left, readErr := os.ReadDir(fixture.phase.Conveyor.tmpDir)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty(), "a refused delivery leaves no scratch behind")
	},
		ginkgo.Entry("the declared target root is not where the import landed the source root",
			assetFixtureOptions{bindings: []map[string]any{{
				"sourceImage": assetSourceName, "sourceRoot": assetSourceRoot,
				"targetRoot": "/build/elsewhere", "proofPath": assetProofPath,
			}}}, "invalid:"),
		ginkgo.Entry("the declared source root is no tree of the source image",
			assetFixtureOptions{
				bindings: []map[string]any{{
					"sourceImage": assetSourceName, "sourceRoot": "/ui/missing",
					"targetRoot": assetTargetRoot, "proofPath": assetProofPath,
				}},
				proofBody: assetProofBody("/ui/missing", 1, []map[string]any{assetProofEntry("app.js", assetAppBody)}),
			}, "no-data:"),
		ginkgo.Entry("the source image never reached this build",
			assetFixtureOptions{bindings: []map[string]any{{
				"sourceImage": "other-ui", "sourceRoot": assetSourceRoot,
				"targetRoot": assetTargetRoot, "proofPath": assetProofPath,
			}}}, "no-data: producer source other-ui is not an earlier explicit import"),
		ginkgo.Entry("the source image ships no proof at the declared path",
			assetFixtureOptions{omitProof: true}, "no-data: source ui has no asset proof at "+assetProofPath),
		ginkgo.Entry("the declared proof path is a directory",
			assetFixtureOptions{proofAsDirectory: true}, "invalid:"),
		ginkgo.Entry("the declared proof path is a symlink",
			assetFixtureOptions{proofAsSymlink: true}, "invalid: asset proof path "+assetProofPath+" traverses a symlink"),
		ginkgo.Entry("the proof is not readable at all",
			assetFixtureOptions{proofBody: []byte(`{"version":1,"assets":[`)}, "invalid: asset proof JSON"),
		ginkgo.Entry("the proof is of a version this build does not understand",
			assetFixtureOptions{proofBody: assetProofBody(assetSourceRoot, 2, []map[string]any{assetProofEntry("app.js", assetAppBody)})},
			"unsupported: asset proof version 2"),
		ginkgo.Entry("the proof covers another source root",
			assetFixtureOptions{proofBody: assetProofBody("/ui/other", 1, []map[string]any{assetProofEntry("app.js", assetAppBody)})},
			"invalid: asset proof source root does not match"),
		ginkgo.Entry("the proof declares one asset path twice",
			assetFixtureOptions{proofBody: assetProofBody(assetSourceRoot, 1, []map[string]any{
				assetProofEntry("app.js", assetAppBody), assetProofEntry("app.js", assetVendorBody),
			})}, "invalid: duplicate asset proof path"),
		ginkgo.Entry("the proof carries an asset path reaching outside the root",
			assetFixtureOptions{proofBody: assetProofBody(assetSourceRoot, 1, []map[string]any{assetProofEntry("../app.js", assetAppBody)})},
			"invalid: asset proof requires clean relative asset paths"),
		ginkgo.Entry("the proof states no version",
			assetFixtureOptions{proofBody: assetProofBody(assetSourceRoot, 1, []map[string]any{assetProofEntry("app.js", assetAppBody)}, "version")},
			"no-data:"),
		ginkgo.Entry("the proof states no source root",
			assetFixtureOptions{proofBody: assetProofBody(assetSourceRoot, 1, []map[string]any{assetProofEntry("app.js", assetAppBody)}, "sourceRoot")},
			"no-data:"),
	)
})
