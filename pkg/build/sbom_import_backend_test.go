package build

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
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
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
		backend.EXPECT().
			GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&imagePkg.Info{Name: "example.org/builder:v1", Repository: "example.org/builder"}, nil).
			AnyTimes()

		img := &buildImage.Image{TargetPlatform: targetPlatform}
		img.SetStages(stages)

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
})
