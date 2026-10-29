package build

import (
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

	scopeOfImport := func(ctx SpecContext, hasStapelBuildSupport bool) nativegate.ImportScope {
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().HasStapelBuildSupport().Return(hasStapelBuildSupport).AnyTimes()
		backend.EXPECT().
			GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&imagePkg.Info{Name: "example.org/builder:v1", Repository: "example.org/builder"}, nil).
			AnyTimes()

		img := &buildImage.Image{TargetPlatform: targetPlatform}
		baseConfig := &config.StapelImageBase{Import: []*config.Import{{
			Export:        &config.Export{ExportBase: &config.ExportBase{Add: "/app", To: "/opt/app", ExcludePaths: []string{"secret"}}},
			From:          "example.org/builder:v1",
			Before:        string(stage.Install),
			ExternalImage: true,
		}}}
		img.SetStages([]stage.Interface{
			stage.GenerateDependenciesBeforeInstallStage(baseConfig, &stage.BaseStageOptions{ImageName: "app", TargetPlatform: targetPlatform}),
		})

		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{
			ContainerBackend: backend,
			imagesTree:       buildImage.NewImagesTree(nil, buildImage.ImagesTreeOptions{}),
		}}}
		scoped, err := phase.resolveScopedImportImages(logging.WithLogger(ctx), img)
		Expect(err).NotTo(HaveOccurred())
		Expect(scoped).To(HaveLen(1))

		return scoped[0].scope
	}

	It("scopes an import to the rsync the legacy Stapel builder copies it with", func(ctx SpecContext) {
		Expect(scopeOfImport(ctx, false)).To(Equal(nativegate.ImportScope{
			Backend:      nativegate.ImportBackendRsync,
			FromPath:     "/app",
			ToPath:       "/opt/app",
			ExcludePaths: []string{"secret"},
		}))
	})

	It("scopes an import to the subtree copy the native builder applies it with", func(ctx SpecContext) {
		Expect(scopeOfImport(ctx, true)).To(Equal(nativegate.ImportScope{
			Backend:      nativegate.ImportBackendCopyRecurse,
			FromPath:     "/app",
			ToPath:       "/opt/app",
			ExcludePaths: []string{"secret"},
		}))
	})
})
