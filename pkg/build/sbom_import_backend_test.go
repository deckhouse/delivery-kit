package build

import (
	"encoding/json"
	"net/http/httptest"
	"strings"

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
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("SBOM import backend", func() {
	const targetPlatform = "linux/amd64"

	importStage := func() stage.Interface {
		baseConfig := &config.StapelImageBase{Import: []*config.Import{{
			Export:        &config.Export{ExportBase: &config.ExportBase{Add: "/app", To: "/opt/app", ExcludePaths: []string{"secret"}}},
			From:          "example.org/builder:v1",
			Before:        string(stage.Install),
			ExternalImage: true,
		}}}

		return stage.GenerateDependenciesBeforeInstallStage(baseConfig, &stage.BaseStageOptions{ImageName: "app", TargetPlatform: targetPlatform})
	}

	scopeOfImport := func(ctx SpecContext, stages []stage.Interface) (nativegate.ImportScope, error) {
		img := &buildImage.Image{TargetPlatform: targetPlatform}
		img.SetStages(stages)

		return scopeOfImportImage(ctx, img)
	}

	// The run reading an import is not necessarily the run that applied it: a stage
	// reused from the cache was copied by whichever builder built it then.
	It("scopes an import to the rsync the stage recorded copying it with", func(ctx SpecContext) {
		Expect(scopeOfImport(ctx, recordingImportBackend("rsync", importStage()))).To(Equal(nativegate.ImportScope{
			Backend:      nativegate.ImportBackendRsync,
			FromPath:     "/app",
			ToPath:       "/opt/app",
			ExcludePaths: []string{"secret"},
		}))
	})

	It("scopes an import to the subtree copy the stage recorded copying it with", func(ctx SpecContext) {
		Expect(scopeOfImport(ctx, recordingImportBackend("copy-recurse", importStage()))).To(Equal(nativegate.ImportScope{
			Backend:      nativegate.ImportBackendCopyRecurse,
			FromPath:     "/app",
			ToPath:       "/opt/app",
			ExcludePaths: []string{"secret"},
		}))
	})

	It("refuses to scope an import of a stage that recorded no backend", func(ctx SpecContext) {
		_, err := scopeOfImport(ctx, recordingImportBackend("", importStage()))
		Expect(err).To(MatchError(ContainSubstring("records no import copy backend")))
	})

	It("refuses to scope an import of a stage that carries no record at all", func(ctx SpecContext) {
		stg := importStage()
		legacy := mock.NewMockLegacyImageInterface(gomock.NewController(GinkgoT()))
		legacy.EXPECT().GetStageDesc().Return(&imagePkg.StageDesc{Info: &imagePkg.Info{Labels: map[string]string{}}}).AnyTimes()
		stg.SetStageImage(&stage.StageImage{Image: legacy})

		_, err := scopeOfImport(ctx, []stage.Interface{stg})
		Expect(err).To(MatchError(ContainSubstring("read the SBOM stage record")))
	})

	It("refuses to scope an import of a stage that is not built", func(ctx SpecContext) {
		_, err := scopeOfImport(ctx, []stage.Interface{importStage()})
		Expect(err).To(MatchError(ContainSubstring("carries no built stage")))
	})

	// The record states the backend of the stage that performed the copy, so a record
	// of another stage would answer for a copy it never performed.
	It("refuses a record that belongs to another stage", func(ctx SpecContext) {
		stg := importStage()
		record, err := json.Marshal(sbomStageRecord{Stage: stage.DependenciesAfterInstall, ImportBackend: "rsync"})
		Expect(err).NotTo(HaveOccurred())
		legacy := mock.NewMockLegacyImageInterface(gomock.NewController(GinkgoT()))
		legacy.EXPECT().GetStageDesc().Return(&imagePkg.StageDesc{Info: &imagePkg.Info{
			Labels: map[string]string{imagePkg.WerfSBOMStageLabel: string(record)},
		}}).AnyTimes()
		stg.SetStageImage(&stage.StageImage{Image: legacy})

		_, err = scopeOfImport(ctx, []stage.Interface{stg})
		Expect(err).To(MatchError(ContainSubstring("belongs to stage dependenciesAfterInstall")))
	})

	// An image reused whole by its content anchor never processes its stages, so no
	// stage of it holds a stage image in this run: what copied the import is read from
	// the stage chain the registry holds for that same image.
	Describe("an image reused whole by its content anchor", func() {
		var repo string

		BeforeEach(func(specCtx SpecContext) {
			Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
			Expect(docker_registry.Init(logging.WithLogger(specCtx), false, false, nil, nil)).To(Succeed())
			server := httptest.NewServer(registry.New())
			DeferCleanup(server.Close)
			repo = strings.TrimPrefix(server.URL, "http://") + "/warm"
		})

		// publishedChain pushes the two stages of such an image - the base stage and the
		// one applying the import - and answers with the descriptor of the last of them.
		publishedChain := func(ctx SpecContext, backend string) *imagePkg.StageDesc {
			GinkgoHelper()
			const parentStageID = "a1b2c3-1"
			const stageDigest = "d4e5f6"

			labeled := func(img v1.Image, labels map[string]string) v1.Image {
				config, err := img.ConfigFile()
				Expect(err).NotTo(HaveOccurred())
				config.Config.Labels = labels
				labeledImg, err := mutate.ConfigFile(img, config)
				Expect(err).NotTo(HaveOccurred())

				return labeledImg
			}
			push := func(tag string, img v1.Image) {
				ref, err := name.NewTag(repo + ":" + tag)
				Expect(err).NotTo(HaveOccurred())
				Expect(remote.Write(ref, img, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
			}

			baseLayer, err := fixtureLayer([]byte("base"))
			Expect(err).NotTo(HaveOccurred())
			base, err := mutate.AppendLayers(empty.Image, baseLayer)
			Expect(err).NotTo(HaveOccurred())
			baseRecord, err := json.Marshal(sbomStageRecord{Stage: stage.From, StageDigest: "a1b2c3"})
			Expect(err).NotTo(HaveOccurred())
			base = labeled(base, map[string]string{imagePkg.WerfSBOMStageLabel: string(baseRecord)})
			push(parentStageID, base)

			importLayer, err := fixtureLayer([]byte("import"))
			Expect(err).NotTo(HaveOccurred())
			imported, err := mutate.AppendLayers(base, importLayer)
			Expect(err).NotTo(HaveOccurred())
			importRecord, err := json.Marshal(sbomStageRecord{
				Stage:         stage.DependenciesBeforeInstall,
				StageDigest:   stageDigest,
				ParentStageID: parentStageID,
				ImportBackend: backend,
			})
			Expect(err).NotTo(HaveOccurred())
			imported = labeled(imported, map[string]string{
				imagePkg.WerfSBOMStageLabel: string(importRecord),
				imagePkg.WerfParentStageID:  parentStageID,
			})
			push(stageDigest+"-2", imported)
			digest, err := imported.Digest()
			Expect(err).NotTo(HaveOccurred())

			return &imagePkg.StageDesc{
				StageID: imagePkg.NewStageID(stageDigest, 2),
				Info:    &imagePkg.Info{Name: repo + ":" + stageDigest + "-2", Repository: repo, RepoDigest: repo + "@" + digest.String()},
			}
		}

		scopeOfReusedImport := func(ctx SpecContext, desc *imagePkg.StageDesc) (nativegate.ImportScope, error) {
			img := &buildImage.Image{TargetPlatform: targetPlatform}
			img.SetStages([]stage.Interface{importStage()})
			img.SetContentTagDesc(desc)

			return scopeOfImportImage(ctx, img)
		}

		It("scopes an import to the backend the published stage recorded", func(ctx SpecContext) {
			Expect(scopeOfReusedImport(ctx, publishedChain(ctx, "rsync"))).To(Equal(nativegate.ImportScope{
				Backend:      nativegate.ImportBackendRsync,
				FromPath:     "/app",
				ToPath:       "/opt/app",
				ExcludePaths: []string{"secret"},
			}))
			Expect(scopeOfReusedImport(ctx, publishedChain(ctx, "copy-recurse"))).To(Equal(nativegate.ImportScope{
				Backend:      nativegate.ImportBackendCopyRecurse,
				FromPath:     "/app",
				ToPath:       "/opt/app",
				ExcludePaths: []string{"secret"},
			}))
		})

		It("refuses an import whose published stage records no backend", func(ctx SpecContext) {
			_, err := scopeOfReusedImport(ctx, publishedChain(ctx, ""))
			Expect(err).To(MatchError(ContainSubstring("records no import copy backend")))
		})
	})
})

func scopeOfImportImage(ctx SpecContext, img *buildImage.Image) (nativegate.ImportScope, error) {
	GinkgoHelper()
	backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
	backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
	backend.EXPECT().
		GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&imagePkg.Info{Name: "example.org/builder:v1", Repository: "example.org/builder"}, nil).
		AnyTimes()

	phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{
		ContainerBackend: backend,
		imagesTree:       buildImage.NewImagesTree(nil, buildImage.ImagesTreeOptions{}),
	}}}
	scoped, err := phase.resolveScopedImportImages(logging.WithLogger(ctx), img)
	if err != nil {
		return nativegate.ImportScope{}, err
	}
	Expect(scoped).To(HaveLen(1))

	return scoped[0].scope, nil
}
