package build

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/werf/common-go/pkg/util"
	"go.uber.org/mock/gomock"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/storage"
	"github.com/werf/werf/v3/pkg/storage/manager"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

const (
	producerPlatform   = "linux/amd64"
	producerSourceName = "fixture-source"
	producerMainBody   = "int main(void) { return 0; }\n"
	producerUnusedBody = "void unused(void) {}\n"
	// producerHelperPath is where an import of an undeclared image lands, holding bytes
	// the declared original also serves.
	producerHelperPath = "/opt/helper/tool.h"
)

// producerSourceLabels is the package metadata the prepared source image carries, the
// only place the packet of the context comes from.
func producerSourceLabels() map[string]string {
	return map[string]string{
		"pkg.name":    producerSourceName,
		"pkg.version": "1",
		"pkg.type":    "source",
		"pkg.arch":    producerPlatform,
		"pkg.default": "false",
	}
}

func producerDeclaration(packages ...map[string]any) string {
	GinkgoHelper()
	if len(packages) == 0 {
		packages = []map[string]any{{
			"sourceImage":    producerSourceName,
			"packageName":    producerSourceName,
			"packageVersion": "1",
			"packageType":    "source",
			"sourcePlatform": producerPlatform,
		}}
	}
	data, err := json.Marshal(map[string]any{
		"version": 1,
		"stages": map[string]any{
			string(stage.Install): map[string]any{"subject": 0, "packages": packages},
		},
	})
	Expect(err).NotTo(HaveOccurred())

	return string(data)
}

// producerImage builds an image out of one layer per file set, with the platform and
// config labels an image of the registry carries.
func producerImage(labels map[string]string, layers ...map[string]string) v1.Image {
	GinkgoHelper()
	img := empty.Image
	for _, files := range layers {
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		for _, path := range slices.Sorted(maps.Keys(files)) {
			body := files[path]
			Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(path, "/"), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})).To(Succeed())
			_, err := writer.Write([]byte(body))
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(writer.Close()).To(Succeed())
		layer, err := fixtureLayer(buf.Bytes())
		Expect(err).NotTo(HaveOccurred())
		img, err = mutate.AppendLayers(img, layer)
		Expect(err).NotTo(HaveOccurred())
	}
	cfg, err := img.ConfigFile()
	Expect(err).NotTo(HaveOccurred())
	cfg.OS, cfg.Architecture = "linux", "amd64"
	cfg.Config.Labels = labels
	img, err = mutate.ConfigFile(img, cfg)
	Expect(err).NotTo(HaveOccurred())

	return img
}

func pushProducerImage(ctx context.Context, reference string, img v1.Image) string {
	GinkgoHelper()
	tag, err := name.NewTag(reference)
	Expect(err).NotTo(HaveOccurred())
	Expect(remote.Write(tag, img, remote.WithContext(ctx))).To(Succeed())
	digest, err := img.Digest()
	Expect(err).NotTo(HaveOccurred())

	return digest.String()
}

func producerStageRecord(stageName stage.StageName, digest, parent, importBackend string) string {
	GinkgoHelper()
	data, err := json.Marshal(sbomStageRecord{Stage: stageName, StageDigest: digest, ParentStageID: parent, ImportBackend: importBackend})
	Expect(err).NotTo(HaveOccurred())

	return string(data)
}

type producerFixtureOptions struct {
	// sourceLabels replace the package metadata of the prepared source image.
	sourceLabels map[string]string
	// declaration replaces the whole producer intent label of the built image.
	declaration string
	// targetMain is what the dependency stage actually shipped at /src/main.c.
	targetMain string
	// includePaths is the scope of the import directive that carried the source.
	includePaths []string
	// importFrom is the image the import directive names, when it is not the
	// source image the declaration points at.
	importFrom string
	// unpinnedSource leaves the resolved dependency result without a digest.
	unpinnedSource bool
	// withoutDeclaration builds the same image without any producer intent.
	withoutDeclaration bool
	// cached is the stage the stages storage answers every lookup with.
	cached *imagePkg.StageDesc
	// installedPacket adds the packages stage a pm install produced: the files it
	// unpacked and the source receipt pm wrote where it opened the packet.
	installedPacket bool
}

// recordingStorageManager answers stage lookups with one prepared result and keeps the
// digests it was asked for, which is how the producer context reaches the cache.
type recordingStorageManager struct {
	manager.StorageManagerInterface
	cached  *imagePkg.StageDesc
	lookups []string
}

func (m *recordingStorageManager) GetStagesStorage() storage.PrimaryStagesStorage { return nil }

func (m *recordingStorageManager) GetSecondaryStagesStorageList() []storage.StagesStorage { return nil }

func (m *recordingStorageManager) GetStageDescSetByDigestFromStagesStorageCached(_ context.Context, _, digest string, _ int64, _ storage.StagesStorage) (imagePkg.StageDescSet, error) {
	m.lookups = append(m.lookups, digest)
	if m.cached == nil {
		return imagePkg.NewStageDescSet(), nil
	}

	return imagePkg.NewStageDescSet(m.cached), nil
}

func (m *recordingStorageManager) SelectSuitableStageDesc(_ context.Context, _ stage.Conveyor, _ stage.Interface, stageDescSet imagePkg.StageDescSet) (*imagePkg.StageDesc, error) {
	for stageDesc := range stageDescSet.Iter() {
		return stageDesc, nil
	}

	return nil, nil
}

// producerCachedStage is a stage the storage can hand back as already built.
func producerCachedStage() *imagePkg.StageDesc {
	return &imagePkg.StageDesc{
		StageID: imagePkg.NewStageID(strings.Repeat("d", 56), 4),
		Info: &imagePkg.Info{
			Name:   "example.org/project/stages:cached",
			Labels: map[string]string{imagePkg.WerfStageContentDigestLabel: "cached-content"},
		},
	}
}

type producerFixture struct {
	phase        *BuildPhase
	img          *buildImage.Image
	stg          stage.Interface
	storage      *recordingStorageManager
	sourceRepo   string
	sourceDigest string
	packetRepo   string
	packetDigest string
	stopRegistry func()
}

// newProducerFixture builds what a producer stage is reached with: a prepared source
// image in a registry, the actual from -> dependenciesBeforeInstall chain that copied it
// into the build, and the phase that is about to calculate the install stage.
func newProducerFixture(ctx context.Context, opts producerFixtureOptions) *producerFixture {
	GinkgoHelper()
	Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
	Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
	server := httptest.NewServer(registry.New())
	DeferCleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")

	labels := opts.sourceLabels
	if labels == nil {
		labels = producerSourceLabels()
	}
	sourceRepo := host + "/fixture/source"
	sourceImg := producerImage(labels, map[string]string{"/src/main.c": producerMainBody, "/src/unused.c": producerUnusedBody})
	sourceDigest := pushProducerImage(ctx, sourceRepo+":prepared", sourceImg)
	sourceRef := sourceRepo + "@" + sourceDigest

	targetMain := opts.targetMain
	if targetMain == "" {
		targetMain = producerMainBody
	}
	stagesRepo := host + "/project/stages"
	fromID := imagePkg.NewStageID(strings.Repeat("a", 56), 1)
	depsID := imagePkg.NewStageID(strings.Repeat("b", 56), 2)
	base := map[string]string{"/bin/sh": "shell", "/src/unused.c": producerUnusedBody}
	fromImg := producerImage(map[string]string{
		imagePkg.WerfSBOMStageLabel: producerStageRecord(stage.From, fromID.Digest, "", ""),
	}, base)
	depsImg := producerImage(map[string]string{
		imagePkg.WerfSBOMStageLabel: producerStageRecord(stage.DependenciesBeforeInstall, depsID.Digest, fromID.String(), "copy-recurse"),
		imagePkg.WerfParentStageID:  fromID.String(),
	}, base, map[string]string{"/src/main.c": targetMain, producerHelperPath: producerUnusedBody})
	pushProducerImage(ctx, stagesRepo+":"+fromID.String(), fromImg)
	depsDigest := pushProducerImage(ctx, stagesRepo+":"+depsID.String(), depsImg)
	previousRef := stagesRepo + "@" + depsDigest
	previousID, previousImg := depsID, depsImg

	// The packages stage of a build that installed a tool packet: pm unpacked its
	// files and wrote the receipt naming where it opened the packet from.
	packetRepo, packetDigest := "", ""
	if opts.installedPacket {
		packetRepo = host + "/fixture/packages/esbuild"
		packetDigest = pushProducerImage(ctx, packetRepo+":packet", producerImage(nil, producerPacketFiles()))
		installed := maps.Clone(producerPacketFiles())
		installed[sources.DefaultPath] = producerPacketReceipt(packetRepo, packetDigest)
		packagesID := imagePkg.NewStageID(strings.Repeat("e", 56), 3)
		packagesImg := producerImage(map[string]string{
			imagePkg.WerfSBOMStageLabel: producerStageRecord(stage.Packages, packagesID.Digest, depsID.String(), ""),
			imagePkg.WerfParentStageID:  depsID.String(),
		}, base, map[string]string{"/src/main.c": targetMain, producerHelperPath: producerUnusedBody}, installed)
		packagesDigest := pushProducerImage(ctx, stagesRepo+":"+packagesID.String(), packagesImg)
		previousRef, previousID, previousImg = stagesRepo+"@"+packagesDigest, packagesID, packagesImg
	}
	previousDesc := &imagePkg.StageDesc{StageID: previousID, Info: &imagePkg.Info{
		Name: stagesRepo + ":" + previousID.String(), Repository: stagesRepo, RepoDigest: previousRef,
	}}

	backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
	backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
	backend.EXPECT().Pull(gomock.Any(), previousRef, container_backend.PullOpts{TargetPlatform: producerPlatform}).Return(nil).AnyTimes()
	backend.EXPECT().SaveImageToStream(gomock.Any(), previousRef).
		DoAndReturn(func(_ any, _ string) (io.ReadCloser, error) { return producerImageStream(previousImg) }).AnyTimes()
	backend.EXPECT().Pull(gomock.Any(), sourceRef, container_backend.PullOpts{TargetPlatform: producerPlatform}).Return(nil).AnyTimes()
	backend.EXPECT().SaveImageToStream(gomock.Any(), sourceRef).
		DoAndReturn(func(_ any, _ string) (io.ReadCloser, error) { return producerImageStream(sourceImg) }).AnyTimes()

	storageManager := &recordingStorageManager{cached: opts.cached}
	phase := newTestBuildPhase(storageManager, nil)
	phase.Conveyor.ContainerBackend = backend
	phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: true}
	phase.Conveyor.tmpDir = GinkgoT().TempDir()
	phase.Conveyor.giterminismManager = stage.NewGiterminismManagerStub(&producerGitRepoStub{LocalGitRepoStub: stage.NewLocalGitRepoStub("abc123")}, stage.NewGiterminismInspectorStub())
	phase.StagesIterator = NewStagesIterator(phase.Conveyor)

	sourceInfo := &imagePkg.Info{Name: sourceRef, Repository: sourceRepo, RepoDigest: sourceRef}
	if opts.unpinnedSource {
		sourceInfo = &imagePkg.Info{Name: sourceRepo + ":prepared", Repository: sourceRepo}
	}
	preparedSource := &buildImage.Image{Name: producerSourceName, TargetPlatform: producerPlatform}
	preparedSource.SetContentTagDesc(&imagePkg.StageDesc{StageID: imagePkg.NewStageID(strings.Repeat("c", 56), 3), Info: sourceInfo})
	phase.Conveyor.imagesTree.AppendImageForTests(preparedSource)

	declaration := opts.declaration
	if declaration == "" {
		declaration = producerDeclaration()
	}
	specLabels := map[string]string{stage.SBOMBuildContextLabel: declaration}
	if opts.withoutDeclaration {
		specLabels = map[string]string{}
	}
	includePaths := opts.includePaths
	if includePaths == nil {
		includePaths = []string{"main.c"}
	}
	importFrom := opts.importFrom
	if importFrom == "" {
		importFrom = producerSourceName
	}
	baseConfig := &config.StapelImageBase{
		Name:      "app",
		ImageSpec: &config.ImageSpec{Labels: specLabels},
		Import: []*config.Import{
			{
				Export: &config.Export{ExportBase: &config.ExportBase{Add: "/src", To: "/src", IncludePaths: includePaths}},
				From:   importFrom,
				Before: string(stage.Install),
			},
			// An import of an image the declaration says nothing about: it lands on the
			// same stage boundary and is no input of this build context.
			{
				Export:        &config.Export{ExportBase: &config.ExportBase{Add: "/opt/helper", To: producerHelperPath}},
				From:          "helper-image:v1",
				Before:        string(stage.Install),
				ExternalImage: true,
			},
		},
	}
	stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: producerPlatform}
	depsStage := stage.GenerateDependenciesBeforeInstallStage(baseConfig, stageOpts)
	depsStage.SetStageImage(&stage.StageImage{Image: &exportLegacyImageStub{stageDesc: previousDesc}})
	producerStage := &producerStageStub{BaseStage: stage.NewBaseStage(stage.Install, stageOpts)}
	stages := []stage.Interface{depsStage}
	phase.StagesIterator.PrevBuiltStage = depsStage
	if opts.installedPacket {
		packagesStage := &producerStageStub{BaseStage: stage.NewBaseStage(stage.Packages, stageOpts)}
		packagesStage.SetStageImage(&stage.StageImage{Image: &exportLegacyImageStub{stageDesc: previousDesc}})
		stages = append(stages, packagesStage)
		phase.StagesIterator.PrevBuiltStage = packagesStage
	}

	img := &buildImage.Image{Name: "app", TargetPlatform: producerPlatform, StapelImageConfig: &config.StapelImage{StapelImageBase: baseConfig}}
	img.SetStages(append(stages, producerStage))

	return &producerFixture{
		phase: phase, img: img, stg: producerStage, storage: storageManager,
		sourceRepo: sourceRepo, sourceDigest: sourceDigest,
		packetRepo: packetRepo, packetDigest: packetDigest, stopRegistry: server.Close,
	}
}

// producerStageStub is an ordinary install stage: it is calculated and prepared like
// any other, and contributes a payload of its own to the stage digest.
type producerStageStub struct {
	*stage.BaseStage
	// fetchErr is what fetching this stage's dependencies fails with.
	fetchErr error
}

var _ stage.Interface = (*producerStageStub)(nil)

func (s *producerStageStub) GetDependencies(_ context.Context, _ stage.Conveyor, _ container_backend.ContainerBackend, _, _ *stage.StageImage, _ container_backend.BuildContextArchiver) (string, error) {
	return "install-payload", nil
}

func (s *producerStageStub) FetchDependencies(_ context.Context, _ stage.Conveyor, _ container_backend.ContainerBackend, _ docker_registry.GenericApiInterface) error {
	return s.fetchErr
}

// producerGitRepoStub answers what preparing a stapel stage asks the local repo for.
type producerGitRepoStub struct {
	*stage.LocalGitRepoStub
}

func (r *producerGitRepoStub) HeadCommitTime(_ context.Context) (*time.Time, error) {
	moment := time.Unix(1700000000, 0).UTC()

	return &moment, nil
}

func producerImageStream(img v1.Image) (io.ReadCloser, error) {
	ref, err := name.NewTag("example.org/saved:latest")
	if err != nil {
		return nil, err
	}
	var saved bytes.Buffer
	if err := tarball.Write(ref, img, &saved); err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(saved.Bytes())), nil
}

// producerWrittenContext reads the context file the stage will be given, by the path the
// private build namespace sees it at.
func producerWrittenContext(input *sbomProducerContext) *buildcontext.Context {
	GinkgoHelper()
	Expect(input.path).To(HavePrefix(producerContextMount + "/"))
	body, err := os.ReadFile(filepath.Join(input.directory, strings.TrimPrefix(input.path, producerContextMount+"/")))
	Expect(err).NotTo(HaveOccurred())
	decoded, err := buildcontext.Decode(body)
	Expect(err).NotTo(HaveOccurred())

	return decoded
}

var _ = Describe("Resolving producer build contexts", func() {
	It("materializes the context of the declared stage from the sources the build actually imported", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newProducerFixture(ctx, producerFixtureOptions{})

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).NotTo(HaveOccurred())
		Expect(input).NotTo(BeNil())
		DeferCleanup(func() { Expect(os.RemoveAll(input.directory)).To(Succeed()) })
		Expect(input.directory).To(HavePrefix(fixture.phase.Conveyor.tmpDir), "the context is materialized in the conveyor's own temp directory")
		Expect(input.checksum).NotTo(BeEmpty())

		written := producerWrittenContext(input)
		Expect(written.Version).To(Equal(1))
		Expect(written.Platform).To(Equal(producerPlatform), "the context targets the platform the image is built for")
		Expect(written.Subject.Name).To(Equal(producerSourceName), "the subject is the prepared package, not the werf image alias")
		Expect(written.Subject.Version).To(Equal("1"))
		Expect(written.Subject.Source.Kind).To(Equal("pm"))
		Expect(written.Subject.Source.Checksum).To(Equal(fixture.sourceDigest))

		Expect(written.Packages).To(HaveLen(1))
		Expect(written.Packages[0].Registry).To(Equal(fixture.sourceRepo))
		Expect(written.Packages[0].Platform).To(Equal(producerPlatform))
		var packet map[string]any
		Expect(json.Unmarshal(written.Packages[0].Packet, &packet)).To(Succeed())
		Expect(packet).To(HaveKeyWithValue("name", producerSourceName))
		Expect(packet).To(HaveKeyWithValue("type", "source"))
		Expect(packet).To(HaveKeyWithValue("default", false))
		Expect(packet).To(HaveKeyWithValue("digest", fixture.sourceDigest), "the packet is pinned to the digest the dependency resolved to")

		Expect(written.Imports).To(Equal([]buildcontext.Import{
			{Path: "/src/main.c", Package: &[]int{0}[0], OriginalPath: "src/main.c"},
		}), "only the file the import scope carried is mapped, though the build holds the rest of the payload too")

		layoutPath := written.Packages[0].Layout
		Expect(layoutPath).To(HavePrefix(producerContextMount + "/"))

		// Nothing below reaches the registry: the stage compiles offline.
		fixture.stopRegistry()
		host := filepath.Join(input.directory, strings.TrimPrefix(layoutPath, producerContextMount+"/"))
		index, err := layout.ImageIndexFromPath(host)
		Expect(err).NotTo(HaveOccurred())
		manifest, err := index.IndexManifest()
		Expect(err).NotTo(HaveOccurred())
		Expect(manifest.Manifests).To(HaveLen(1))
		pin, err := v1.NewHash(fixture.sourceDigest)
		Expect(err).NotTo(HaveOccurred())
		Expect(manifest.Manifests[0].Digest).To(Equal(pin), "the layout keeps the pinned manifest as its own root")
		exported, err := index.Image(pin)
		Expect(err).NotTo(HaveOccurred())
		pkg, err := original.NewOriginalPackage(exported)
		Expect(err).NotTo(HaveOccurred())
		reader, err := pkg.Open("src/main.c")
		Expect(err).NotTo(HaveOccurred())
		body, err := io.ReadAll(reader)
		Expect(reader.Close()).To(Succeed())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal(producerMainBody))
	})

	It("materializes into a conveyor temp directory no earlier stage had to create", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newProducerFixture(ctx, producerFixtureOptions{})
		// A warm build reuses every preceding stage from the cache, so nothing has
		// created the conveyor's temp directory yet.
		fixture.phase.Conveyor.tmpDir = filepath.Join(fixture.phase.Conveyor.tmpDir, "not-created")

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).NotTo(HaveOccurred())
		Expect(input).NotTo(BeNil())
		DeferCleanup(func() { Expect(os.RemoveAll(input.directory)).To(Succeed()) })

		Expect(fixture.phase.Conveyor.tmpDir).To(BeADirectory())
		Expect(input.directory).To(BeADirectory())
		Expect(producerWrittenContext(input).Imports).To(HaveLen(1))
	})

	It("keeps the checksum bound to the context it wrote, not to the host directory it wrote it in", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newProducerFixture(ctx, producerFixtureOptions{})

		first, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(first.directory)).To(Succeed()) })
		second, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(second.directory)).To(Succeed()) })

		Expect(second.directory).NotTo(Equal(first.directory))
		Expect(second.checksum).To(Equal(first.checksum), "two materializations of one plan select the same cached stage")

		widened := newProducerFixture(ctx, producerFixtureOptions{includePaths: []string{}})
		other, err := widened.phase.producerContext(ctx, widened.img, widened.stg)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(other.directory)).To(Succeed()) })
		Expect(producerWrittenContext(other).Imports).To(HaveLen(2), "the widened scope carried the rest of the payload too")
		Expect(other.checksum).NotTo(Equal(first.checksum), "a changed import scope is a different build context")
	})

	It("claims no mapping for a path whose bytes the stage no longer holds", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		fixture := newProducerFixture(ctx, producerFixtureOptions{targetMain: "int main(void) { return 1; }\n"})

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(input.directory)).To(Succeed()) })

		Expect(producerWrittenContext(input).Imports).To(BeEmpty(), "changed bytes leave the compiler without an input rather than a guessed one")
	})

	It("leaves an import the declaration says nothing about out of the context it plans", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		// The widened scope of the declared source would carry everything it could; the
		// undeclared import lands bytes the declared original serves as well.
		fixture := newProducerFixture(ctx, producerFixtureOptions{includePaths: []string{}})

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).NotTo(HaveOccurred(), "an import of an image with no prepared package is not a reason to refuse the context")
		DeferCleanup(func() { Expect(os.RemoveAll(input.directory)).To(Succeed()) })

		written := producerWrittenContext(input)
		Expect(written.Packages).To(HaveLen(1), "the undeclared source image is no package of this context")
		paths := make([]string, 0, len(written.Imports))
		for _, mapping := range written.Imports {
			paths = append(paths, mapping.Path)
		}
		Expect(paths).To(ConsistOf("/src/main.c", "/src/unused.c"))
		Expect(paths).NotTo(ContainElement(producerHelperPath), "equal bytes carried by an undeclared import bind to no original")
	})

	DescribeTable("refuses a producer context it cannot prove", func(specCtx SpecContext, opts producerFixtureOptions, expected string) {
		ctx := logging.WithLogger(specCtx)
		fixture := newProducerFixture(ctx, opts)

		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		Expect(err).To(MatchError(ContainSubstring(expected)))
		Expect(input).To(BeNil())

		left, readErr := os.ReadDir(fixture.phase.Conveyor.tmpDir)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(left).To(BeEmpty(), "a refused context leaves no scratch behind")
	},
		Entry("the prepared source is not the package the stage declared",
			producerFixtureOptions{declaration: producerDeclaration(map[string]any{
				"sourceImage": producerSourceName, "packageName": producerSourceName,
				"packageVersion": "2", "packageType": "source", "sourcePlatform": producerPlatform,
			})},
			"invalid: producer source fixture-source has unexpected version"),
		Entry("the declared platform is not one the package serves",
			producerFixtureOptions{declaration: producerDeclaration(map[string]any{
				"sourceImage": producerSourceName, "packageName": producerSourceName,
				"packageVersion": "1", "packageType": "source", "sourcePlatform": "linux/arm64",
			})},
			"original image platform linux/amd64/ does not match linux/arm64"),
		Entry("no earlier stage imported the declared source",
			producerFixtureOptions{importFrom: "other-source"},
			"no-data: producer source fixture-source is not an earlier explicit import"),
		Entry("the dependency result was never pinned to a digest",
			producerFixtureOptions{unpinnedSource: true},
			"no-data: producer source fixture-source has no resolved dependency digest"),
		Entry("the prepared source carries no package metadata",
			producerFixtureOptions{sourceLabels: map[string]string{"org.opencontainers.image.title": "source"}},
			"no package labels"),
		Entry("the producer intent is not readable",
			producerFixtureOptions{declaration: `{"version":1,"stages":{"install":{`},
			"parse SBOM build context declaration: invalid"),
	)

	It("plans no context for a stage, or an image, that declares none", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		phase := newTestBuildPhase(nil, nil)
		phase.Conveyor.ContainerBackend = backend
		phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: true}
		phase.StagesIterator = NewStagesIterator(phase.Conveyor)
		stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: producerPlatform}
		stg := &producerStageStub{BaseStage: stage.NewBaseStage(stage.Install, stageOpts)}

		declared := &buildImage.Image{Name: "app", TargetPlatform: producerPlatform, StapelImageConfig: &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			ImageSpec: &config.ImageSpec{Labels: map[string]string{stage.SBOMBuildContextLabel: producerDeclaration()}},
		}}}
		undeclared := &buildImage.Image{Name: "app", TargetPlatform: producerPlatform, StapelImageConfig: &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			ImageSpec: &config.ImageSpec{Labels: map[string]string{"org.opencontainers.image.title": "app"}},
		}}}
		dockerfile := &buildImage.Image{Name: "app", TargetPlatform: producerPlatform, IsDockerfileImage: true}

		Expect(producerDeclarationPresent(declared)).To(BeTrue())
		Expect(producerDeclarationPresent(undeclared)).To(BeFalse())
		Expect(producerDeclarationPresent(dockerfile)).To(BeFalse())

		// A stage outside the declaration, and an image with no declaration at all, are
		// planned without reading a single image.
		input, err := phase.producerContext(ctx, declared, &producerStageStub{BaseStage: stage.NewBaseStage(stage.Setup, stageOpts)})
		Expect(err).NotTo(HaveOccurred())
		Expect(input).To(BeNil())

		input, err = phase.producerContext(ctx, undeclared, stg)
		Expect(err).NotTo(HaveOccurred())
		Expect(input).To(BeNil())

		phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: false}
		input, err = phase.producerContext(ctx, declared, stg)
		Expect(err).NotTo(HaveOccurred())
		Expect(input).To(BeNil(), "an SBOM-less build never materializes a producer context")
	})

	It("calculates the anchor digest of a declared image but never reuses a stage by it", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		storageManager := &recordingStorageManager{}
		phase := newTestBuildPhase(storageManager, nil)
		phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: true}

		img := newTestImage("app", true)
		img.Conveyor = phase.Conveyor
		// An image whose anchor inputs are only known once its dependencies are
		// resolved: the prepass leaves its digest to this call.
		img.RequiresResolvedDependencyInputs = true
		img.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			ImageSpec: &config.ImageSpec{Labels: map[string]string{stage.SBOMBuildContextLabel: producerDeclaration()}},
		}}
		anchor := newContentDependenciesStub(stage.ImageSpec, "anchor-deps")
		anchor.SetContentAnchor(true)
		img.SetStages([]stage.Interface{anchor})
		phase.Conveyor.imagesTree.SetImagesGraphForTests(newTestImagesGraph(img))
		phase.StagesIterator = NewStagesIterator(phase.Conveyor)

		Expect(phase.resolveContentAnchor(ctx, img, false)).To(Succeed())

		Expect(img.GetAnchorDigest()).NotTo(BeEmpty(), "the image spec stage of a declared image still needs its anchor digest")
		Expect(storageManager.lookups).To(BeEmpty(), "the declared producer stages are built, never reused by anchor")

		img.StapelImageConfig.ImageBaseConfig().ImageSpec.Labels = map[string]string{}
		Expect(phase.resolveContentAnchor(ctx, img, false)).To(Succeed())
		Expect(storageManager.lookups).To(HaveLen(1), "an image without the declaration still resolves its anchor from the cache")
	})

	It("hands no producer context of one stage to the clone that builds another", func() {
		phase := newTestBuildPhase(nil, nil)
		phase.producerInput = &sbomProducerContext{directory: "/tmp/producer-context", path: producerContextMount + "/context.json", checksum: "sum"}

		cloned, ok := phase.Clone().(*BuildPhase)
		Expect(ok).To(BeTrue())
		Expect(cloned.producerInput).To(BeNil())
		Expect(phase.producerInput).NotTo(BeNil(), "the clone does not take the context away from the phase that owns it")
	})

	Describe("calculating the stage that consumes it", func() {
		calculate := func(ctx context.Context, fixture *producerFixture) (bool, error) {
			GinkgoHelper()
			found, unlock, err := fixture.phase.calculateStage(ctx, fixture.img, fixture.stg)
			if unlock != nil {
				unlock()
			}
			if fixture.phase.producerInput != nil {
				directory := fixture.phase.producerInput.directory
				DeferCleanup(func() { Expect(os.RemoveAll(directory)).To(Succeed()) })
			}

			return found, err
		}

		It("looks the stage up by a digest the materialized context is part of", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			declared := newProducerFixture(ctx, producerFixtureOptions{})
			plain := newProducerFixture(ctx, producerFixtureOptions{withoutDeclaration: true})
			// The same stage payload, the same prepared source, a different scope of the
			// import that carried it into the build.
			rescoped := newProducerFixture(ctx, producerFixtureOptions{includePaths: []string{}})

			found, err := calculate(ctx, declared)
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeFalse())
			Expect(calculate(ctx, plain)).To(BeFalse())
			Expect(calculate(ctx, rescoped)).To(BeFalse())

			Expect(declared.storage.lookups).To(Equal([]string{declared.stg.GetDigest()}), "the stage is looked up by the digest it was given")
			Expect(declared.stg.GetDigest()).NotTo(Equal(plain.stg.GetDigest()),
				"a stage built against a materialized context is not the cached stage of the same recipe without one")
			Expect(declared.stg.GetDigest()).NotTo(Equal(rescoped.stg.GetDigest()),
				"a context built from other imported sources selects another stage")
			Expect(declared.phase.producerInput).NotTo(BeNil(), "the calculated context stays with the phase that will build the stage")
			Expect(plain.phase.producerInput).To(BeNil())
		})

		It("reuses the stage the context selects, without building it again", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			cached := producerCachedStage()
			fixture := newProducerFixture(ctx, producerFixtureOptions{cached: cached})

			found, err := calculate(ctx, fixture)
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeTrue())
			Expect(fixture.storage.lookups).To(Equal([]string{fixture.stg.GetDigest()}))
			Expect(fixture.stg.GetStageImage().Image.GetStageDesc()).To(BeIdenticalTo(cached))
			Expect(fixture.stg.GetContentDigest()).To(Equal("cached-content"), "the content digest of the reused stage is its own")
		})

		It("refuses the stage before reaching the cache when the context cannot be proven", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			fixture := newProducerFixture(ctx, producerFixtureOptions{unpinnedSource: true, cached: producerCachedStage()})

			_, err := calculate(ctx, fixture)
			Expect(err).To(MatchError(ContainSubstring("producer context for install: no-data: producer source fixture-source has no resolved dependency digest")))
			Expect(fixture.storage.lookups).To(BeEmpty(), "an available cached stage is no reason to skip proving the context")

			// The same build without a producer intent still reuses its cached stage.
			plain := newProducerFixture(ctx, producerFixtureOptions{withoutDeclaration: true, unpinnedSource: true, cached: producerCachedStage()})
			Expect(calculate(ctx, plain)).To(BeTrue())
			Expect(plain.storage.lookups).To(HaveLen(1))
		})

		It("mounts the materialized context read-only and names it in the build environment", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			fixture := newProducerFixture(ctx, producerFixtureOptions{})
			_, err := calculate(ctx, fixture)
			Expect(err).NotTo(HaveOccurred())
			input := fixture.phase.producerInput
			Expect(input).NotTo(BeNil())

			stageImage := stage.NewStageImage(fixture.phase.Conveyor.ContainerBackend, "base", container_backend.NewLegacyStageImage(nil, "stage", fixture.phase.Conveyor.ContainerBackend, producerPlatform))
			fixture.stg.SetStageImage(stageImage)
			Expect(fixture.phase.prepareStageInstructions(ctx, fixture.img, fixture.stg)).To(Succeed())

			builder, ok := stageImage.Builder.StapelStageBuilder().(*stage_builder.StapelStageBuilder)
			Expect(ok).To(BeTrue())
			Expect(builder.BuildVolumes).To(ContainElement(input.directory+":"+producerContextMount+":ro"),
				"the stage reads the host scratch, and only reads it")
			Expect(builder.BuildTimeEnvs).To(HaveKeyWithValue("SBOM_BUILD_CONTEXT", input.path),
				"the compiler is pointed at the context by the path the namespace sees")
			Expect(input.path).To(HavePrefix(producerContextMount + "/"))
		})
		// A bootstrap image publishes nothing of its own composition, and the compilers
		// its stages run are the instrumented ones that still need to be told which
		// prepared source they compile.
		It("materializes and mounts the context of a bootstrap image, which converges nothing", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			var declaration map[string]any
			Expect(json.Unmarshal([]byte(producerDeclaration()), &declaration)).To(Succeed())
			declaration["bootstrap"] = true
			bootstrap, err := json.Marshal(declaration)
			Expect(err).NotTo(HaveOccurred())

			fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: string(bootstrap)})
			_, err = calculate(ctx, fixture)
			Expect(err).NotTo(HaveOccurred())
			input := fixture.phase.producerInput
			Expect(input).NotTo(BeNil())
			Expect(producerWrittenContext(input).Packages).To(HaveLen(1), "the stage is built against the prepared source its recipe names")

			stageImage := stage.NewStageImage(fixture.phase.Conveyor.ContainerBackend, "base", container_backend.NewLegacyStageImage(nil, "stage", fixture.phase.Conveyor.ContainerBackend, producerPlatform))
			fixture.stg.SetStageImage(stageImage)
			Expect(fixture.phase.prepareStageInstructions(ctx, fixture.img, fixture.stg)).To(Succeed())
			builder, ok := stageImage.Builder.StapelStageBuilder().(*stage_builder.StapelStageBuilder)
			Expect(ok).To(BeTrue())
			Expect(builder.BuildVolumes).To(ContainElement(input.directory + ":" + producerContextMount + ":ro"))
			Expect(builder.BuildTimeEnvs).To(HaveKeyWithValue("SBOM_BUILD_CONTEXT", input.path))

			Expect(fixture.phase.convergePlatformImageSbom(ctx, fixture.img.Name, fixture.img, nil, "", nil)).To(Succeed(),
				"nothing of a bootstrap image is converged, stages or no stages")

			// What that recipe compiles is also what a mapping of an image importing
			// from this toolchain may name, read off the prepared source itself.
			packages, err := fixture.phase.bootstrapSourcePackages(ctx, fixture.img)
			Expect(err).NotTo(HaveOccurred())
			Expect(packages).To(HaveLen(1))
			Expect(packages[0].Platform).To(Equal(producerPlatform))
			Expect(string(packages[0].Packet)).To(ContainSubstring(producerSourceName))
		})

		// The image that imports from the toolchain is the one that has to hand those
		// prepared sources to the verification.
		It("hands the verification the prepared sources of every bootstrap source it maps", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			var declaration map[string]any
			Expect(json.Unmarshal([]byte(producerDeclaration()), &declaration)).To(Succeed())
			declaration["bootstrap"] = true
			bootstrap, err := json.Marshal(declaration)
			Expect(err).NotTo(HaveOccurred())

			fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: string(bootstrap)})
			fixture.phase.Conveyor.imagesTree.AppendImageForTests(fixture.img)
			importing := &buildImage.Image{Name: "strict", TargetPlatform: producerPlatform}
			imports := []scopedImportImage{{resolvedImportImage: resolvedImportImage{imageName: fixture.img.Name, bootstrap: true}}}
			mapped := map[string][]nativegate.ImportOriginal{fixture.img.Name: {
				{Root: "/usr/local/go/src", OriginalPath: "src", PackageName: producerSourceName, PackageVersion: "1"},
			}}

			packages, err := fixture.phase.bootstrapImportPackages(ctx, importing, imports, mapped)
			Expect(err).NotTo(HaveOccurred())
			Expect(packages[fixture.img.Name]).To(HaveLen(1))
			Expect(string(packages[fixture.img.Name][0].Packet)).To(ContainSubstring(producerSourceName))

			unmapped, err := fixture.phase.bootstrapImportPackages(ctx, importing, imports, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(unmapped).To(BeEmpty(), "a source nothing is mapped to is not read at all")
		})

		It("reads no prepared source a bootstrap recipe names something else than it is", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			var declaration map[string]any
			Expect(json.Unmarshal([]byte(producerDeclaration(map[string]any{
				"sourceImage":    producerSourceName,
				"packageName":    producerSourceName,
				"packageVersion": "2",
				"packageType":    "source",
				"sourcePlatform": producerPlatform,
			})), &declaration)).To(Succeed())
			declaration["bootstrap"] = true
			bootstrap, err := json.Marshal(declaration)
			Expect(err).NotTo(HaveOccurred())

			fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: string(bootstrap)})

			_, err = fixture.phase.bootstrapSourcePackages(ctx, fixture.img)
			Expect(err).To(MatchError(ContainSubstring("invalid: producer source " + producerSourceName + " has unexpected version")))
		})

		It("leaves no earlier materialization behind when the stage is calculated again", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			fixture := newProducerFixture(ctx, producerFixtureOptions{})

			_, err := calculate(ctx, fixture)
			Expect(err).NotTo(HaveOccurred())
			first := fixture.phase.producerInput
			Expect(first).NotTo(BeNil())

			_, err = calculate(ctx, fixture)
			Expect(err).NotTo(HaveOccurred())
			second := fixture.phase.producerInput
			Expect(second).NotTo(BeNil())
			Expect(second.directory).NotTo(Equal(first.directory))
			Expect(first.directory).NotTo(BeADirectory(), "a recalculated stage does not leak the scratch of the plan it replaced")
			Expect(producerWrittenContext(second).Imports).To(HaveLen(1), "the plan the stage will be built with is intact")
		})

		It("binds the anchor of a declared image to the stage it is built on", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			anchorOf := func(declared bool, previous *imagePkg.StageDesc) string {
				GinkgoHelper()
				phase := newTestBuildPhase(&recordingStorageManager{}, nil)
				phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: true}
				phase.StagesIterator = NewStagesIterator(phase.Conveyor)

				img := newTestImage("app", true)
				img.Conveyor = phase.Conveyor
				labels := map[string]string{}
				if declared {
					labels[stage.SBOMBuildContextLabel] = producerDeclaration()
				}
				img.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{ImageSpec: &config.ImageSpec{Labels: labels}}}
				// One holistic anchor digest, whatever the stages below it turned out to be.
				img.SetAnchorDigest("holistic-anchor")
				anchor := stage.NewBaseStage(stage.ImageSpec, &stage.BaseStageOptions{ImageName: "app"})
				anchor.SetContentAnchor(true)
				anchorStage := &producerStageStub{BaseStage: anchor}
				img.SetStages([]stage.Interface{anchorStage})

				built := stage.NewBaseStage(stage.Install, &stage.BaseStageOptions{ImageName: "app"})
				builtStage := &producerStageStub{BaseStage: built}
				builtStage.SetStageImage(&stage.StageImage{Image: &exportLegacyImageStub{stageDesc: previous}})
				phase.StagesIterator.PrevBuiltStage = builtStage
				phase.StagesIterator.PrevNonEmptyStage = builtStage

				_, unlock, err := phase.calculateStage(ctx, img, anchorStage)
				if unlock != nil {
					unlock()
				}
				Expect(err).NotTo(HaveOccurred())
				Expect(img.GetAnchorDigest()).To(Equal("holistic-anchor"), "the anchor digest of the image is not rewritten")

				return anchorStage.GetDigest()
			}
			older := &imagePkg.StageDesc{StageID: imagePkg.NewStageID(strings.Repeat("e", 56), 10), Info: &imagePkg.Info{Name: "repo:install-old"}}
			newer := &imagePkg.StageDesc{StageID: imagePkg.NewStageID(strings.Repeat("f", 56), 10), Info: &imagePkg.Info{Name: "repo:install-new"}}

			bound := anchorOf(true, older)
			Expect(bound).NotTo(Equal(anchorOf(true, newer)),
				"an image rebuilt against another producer context does not adopt the final image of the old one")
			Expect(bound).To(Equal(anchorOf(true, older)), "the same build selects the same stage twice")
			Expect(anchorOf(false, older)).To(Equal(anchorOf(false, newer)),
				"an image that declares no producer context keeps the plain holistic anchor")
			Expect(anchorOf(false, older)).To(Equal("holistic-anchor"))

			// The stage digest travels in the metadata tag of a published image, which an
			// OCI reference has to hold.
			Expect(bound).To(HaveLen(len(strings.Repeat("e", 56))), "the anchor digest is a stage digest like any other")
			tag := fmt.Sprintf(storage.RepoImageMetadataByCommitRecord_TagFormat,
				util.LegacyMurmurHash("app"), strings.Repeat("c", 40), imagePkg.NewStageID(bound, 1700000000000).String())
			_, err := name.NewTag("example.org/project/stages:" + tag)
			Expect(err).NotTo(HaveOccurred(), "the metadata tag of a stage carrying this digest must stay a valid reference")
		})

		It("takes the materialized context away from the phase when the stage ends", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
			Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

			directory := GinkgoT().TempDir()
			contextFile := filepath.Join(directory, "context.json")
			Expect(os.WriteFile(contextFile, []byte(`{"version":1}`), 0o444)).To(Succeed())
			phase := newTestBuildPhase(nil, nil)
			phase.Conveyor.ContainerBackend = mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			phase.StagesIterator = NewStagesIterator(phase.Conveyor)
			phase.producerInput = &sbomProducerContext{directory: directory, path: producerContextMount + "/context.json", checksum: "sum"}
			stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: producerPlatform}
			stg := &producerStageStub{BaseStage: stage.NewBaseStage(stage.Install, stageOpts), fetchErr: errors.New("dependency is gone")}

			err := phase.onImageStage(ctx, newTestImage("app", true), stg)

			Expect(err).To(MatchError(ContainSubstring("dependency is gone")))
			Expect(phase.producerInput).To(BeNil(), "a failed stage leaves no context behind for the next one")
			Expect(directory).NotTo(BeADirectory(), "the host scratch of the context is removed with it")
		})
	})
})
