package build

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/attestation"
	buildImage "github.com/werf/werf/v2/pkg/build/image"
	"github.com/werf/werf/v2/pkg/build/stage"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/docker_registry"
	werfImage "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/pkg/werf"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("SbomStep PropagateArtifacts", func() {
	var (
		server     *httptest.Server
		srcRepo    string
		finalRepo  string
		cacheRepo  string
		srcDigest  string
		remoteOpts []remote.Option
		mutations  atomic.Int64
	)

	pushRandomImage := func(ctx SpecContext, repo string) string {
		img, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		ref, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(ref, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())

		dgst, err := img.Digest()
		Expect(err).To(Succeed())
		return dgst.String()
	}

	copyImageByDigest := func(ctx SpecContext, fromRepo, toRepo, digest string) {
		fromRef, err := name.NewDigest(fromRepo + "@" + digest)
		Expect(err).To(Succeed())
		img, err := remote.Image(fromRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())

		toRef, err := name.NewDigest(toRepo + "@" + digest)
		Expect(err).To(Succeed())
		Expect(remote.Write(toRef, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
	}

	stageDescFor := func(repo, digest string) *werfImage.StageDesc {
		return &werfImage.StageDesc{
			StageID: &werfImage.StageID{},
			Info: &werfImage.Info{
				Repository: repo,
				RepoDigest: repo + "@" + digest,
			},
		}
	}

	cacheStorage := func(address string) storage.StagesStorage {
		s := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))
		s.EXPECT().Address().Return(address).AnyTimes()
		s.EXPECT().String().Return(address).AnyTimes()
		return s
	}

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		handler := registry.New()
		mutations.Store(0)
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				mutations.Add(1)
			}
			handler.ServeHTTP(w, r)
		}))
		host := strings.TrimPrefix(server.URL, "http://")
		srcRepo = host + "/test/stages"
		finalRepo = host + "/test/final"
		cacheRepo = host + "/test/cache"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}

		srcDigest = pushRandomImage(ctx, srcRepo)

		srcStore := artifact.NewOCIStore(srcRepo, "app", remoteOpts...)
		Expect(srcStore.Attach(ctx, srcDigest, attestation.DSSEMediaType, []byte(`{"v":1}`), "checksum-v1", "", "")).To(Succeed())
	})

	AfterEach(func() {
		server.Close()
	})

	DescribeTable("AfterImages preserves check mode for fork artifacts", func(ctx SpecContext, check, generate bool) {
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		GinkgoT().Setenv("WERF_EXTERNAL_REFS_SERVER_URL", server.URL)
		srcDigest = pushRandomImage(ctx, srcRepo)
		copyImageByDigest(ctx, srcRepo, finalRepo, srcDigest)
		copyImageByDigest(ctx, srcRepo, cacheRepo, srcDigest)
		desc := &werfImage.StageDesc{StageID: werfImage.NewStageID("digest", 1), Info: &werfImage.Info{Name: srcRepo + "@" + srcDigest, Repository: srcRepo, RepoDigest: srcRepo + "@" + srcDigest}}
		finalDesc := &werfImage.StageDesc{StageID: desc.StageID, Info: &werfImage.Info{Name: finalRepo + "@" + srcDigest, Repository: finalRepo, RepoDigest: finalRepo + "@" + srcDigest}}
		sm := &artifactPhaseStorageManager{primary: &artifactPhasePrimary{address: srcRepo}, final: cacheStorage(finalRepo), finalDesc: finalDesc, caches: []storage.StagesStorage{cacheStorage(cacheRepo)}}
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		if generate && !check {
			backend.EXPECT().Pull(gomock.Any(), desc.Info.Name, gomock.Any()).Return(nil)
			backend.EXPECT().GenerateSBOM(gomock.Any(), gomock.Any()).Return([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":"app","bom-ref":"app"}},"components":[]}`), nil)
		}
		cfg := config.NewWerfConfig(&config.Meta{Project: "artifact-check", Build: config.MetaBuild{Platform: []string{"linux/amd64"}, Sbom: &config.MetaBuildSbom{Enable: generate}}}, []config.ImageInterface{&config.StapelImage{StapelImageBase: &config.StapelImageBase{Name: "app", From: "scratch", FromExternal: true, Git: &config.GitManager{}}}})
		reader := &artifactPhaseFileReader{}
		conveyor := &Conveyor{werfConfig: cfg, ContainerBackend: backend, StorageManager: sm, giterminismManager: &artifactPhaseGiterminism{reader: reader}, serviceRWMutex: make(map[string]*sync.RWMutex), ConveyorOptions: ConveyorOptions{TargetPlatforms: []string{"linux/amd64"}, ParallelTasksLimit: 1}}
		conveyor.imagesTree = buildImage.NewImagesTree(cfg, buildImage.ImagesTreeOptions{ImagesToProcess: config.ImagesToProcess{ImageNameList: []string{"app"}}, CommonImageOptions: buildImage.CommonImageOptions{Conveyor: conveyor, ContainerBackend: backend}})
		Expect(conveyor.imagesTree.Calculate(ctx)).To(Succeed())
		Expect(conveyor.imagesTree.GetImages()).To(HaveLen(1))
		img, err := buildImage.NewImage(ctx, "linux/amd64", "app", buildImage.NoBaseImage, buildImage.ImageOptions{IsFinal: true, Vex: &config.Vex{Document: "vex.json"}})
		Expect(err).To(Succeed())
		stg := stage.NewBaseStage(stage.ImageSpec, &stage.BaseStageOptions{ImageName: "app"})
		stageImage := container_backend.NewLegacyStageImage(nil, desc.Info.Name, backend, "linux/amd64")
		stageImage.SetStageDesc(desc)
		stg.SetStageImage(&stage.StageImage{Image: stageImage})
		img.SetLastNonEmptyStage(stg)
		*conveyor.imagesTree.GetImages()[0] = *img
		phase := NewBuildPhase(conveyor, BuildPhaseOptions{ShouldBeBuiltMode: check, BuildOptions: BuildOptions{SkipImageMetadataPublication: true, SkipAddManagedImagesRecords: true, ReportPath: filepath.Join(GinkgoT().TempDir(), "report.json"), ReportFormat: ReportJSON}})
		mutations.Store(0)
		Expect(phase.AfterImages(ctx)).To(Succeed())
		Expect(sm.copyOptions.ShouldBeBuiltMode).To(Equal(check), "final-image existence validation must retain check mode")
		reportData, err := os.ReadFile(phase.ReportPath)
		Expect(err).To(Succeed())
		var report struct{ Images map[string]ReportImageRecord }
		Expect(json.Unmarshal(reportData, &report)).To(Succeed())
		Expect(report.Images).To(HaveKey("app"))
		if check {
			Expect(mutations.Load()).To(BeZero(), "check mode must not write any registry objects")
			Expect(reader.reads).To(BeZero())
		} else {
			Expect(mutations.Load()).To(BeNumerically(">", 0))
			Expect(reader.reads).To(Equal(1))
		}
		sourceStore := artifact.NewOCIStore(srcRepo, "app", remoteOpts...)
		_, found, err := attestation.FindAttachedArtifact(ctx, sourceStore, srcDigest, attestation.PredicateKindOpenVEX)
		Expect(err).To(Succeed())
		Expect(found).To(Equal(!check), "VEX publication into primary storage")
		for _, repo := range []string{srcRepo, finalRepo, cacheRepo} {
			store := artifact.NewOCIStore(repo, "app", remoteOpts...)
			_, found, err := attestation.FindAttachedArtifact(ctx, store, srcDigest, attestation.PredicateKindCycloneDX)
			Expect(err).To(Succeed())
			Expect(found).To(Equal(generate && !check), repo)
		}
	}, Entry("check with SBOM and VEX configured", true, true), Entry("normal SBOM and VEX publication", false, true), Entry("check with VEX only", true, false), Entry("normal VEX publication", false, false))

	It("should copy the SBOM into the final repo", func(ctx SpecContext) {
		copyImageByDigest(ctx, srcRepo, finalRepo, srcDigest)

		step := &sbomStep{}
		Expect(step.PropagateArtifacts(ctx, "app", stageDescFor(srcRepo, srcDigest), stageDescFor(finalRepo, srcDigest), nil)).To(Succeed())

		finalStore := artifact.NewOCIStore(finalRepo, "app", remoteOpts...)
		content, err := finalStore.GetAttachedContent(ctx, srcDigest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))
	})

	It("should copy the SBOM into cache repos", func(ctx SpecContext) {
		copyImageByDigest(ctx, srcRepo, cacheRepo, srcDigest)

		step := &sbomStep{}
		caches := []storage.StagesStorage{
			cacheStorage(storage.LocalStorageAddress),
			cacheStorage(srcRepo),
			cacheStorage(cacheRepo),
		}
		Expect(step.PropagateArtifacts(ctx, "app", stageDescFor(srcRepo, srcDigest), nil, caches)).To(Succeed())

		cacheStore := artifact.NewOCIStore(cacheRepo, "app", remoteOpts...)
		content, err := cacheStore.GetAttachedContent(ctx, srcDigest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))
	})

	It("should do nothing without a final repo and caches", func(ctx SpecContext) {
		step := &sbomStep{}
		Expect(step.PropagateArtifacts(ctx, "app", stageDescFor(srcRepo, srcDigest), nil, nil)).To(Succeed())
	})

	It("should skip the final repo when it matches the stages repo", func(ctx SpecContext) {
		step := &sbomStep{}
		Expect(step.PropagateArtifacts(ctx, "app", stageDescFor(srcRepo, srcDigest), stageDescFor(srcRepo, srcDigest), nil)).To(Succeed())
	})

	It("should not fail when a cache repo is unreachable", func(ctx SpecContext) {
		step := &sbomStep{}
		caches := []storage.StagesStorage{cacheStorage("127.0.0.1:1/unreachable/cache")}
		Expect(step.PropagateArtifacts(ctx, "app", stageDescFor(srcRepo, srcDigest), nil, caches)).To(Succeed())
	})

	It("should fail when the final repo copy fails", func(ctx SpecContext) {
		step := &sbomStep{}
		err := step.PropagateArtifacts(ctx, "app", stageDescFor(srcRepo, srcDigest), stageDescFor("127.0.0.1:1/unreachable/final", srcDigest), nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("copy attached artifacts into final repo"))
	})
})
