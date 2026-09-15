package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/build/image"
	"github.com/werf/werf/v2/pkg/build/stage"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
	imagePkg "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("resolveImportImages", func() {
	imageWithExternalImports := func(refs ...string) *image.Image {
		imports := make([]*config.Import, 0, len(refs))
		for _, ref := range refs {
			imports = append(imports, &config.Import{
				Export:        &config.Export{},
				From:          ref,
				Before:        string(stage.Install),
				ExternalImage: true,
			})
		}

		img := &image.Image{}
		img.SetStages([]stage.Interface{
			stage.GenerateDependenciesBeforeInstallStage(
				&config.StapelImageBase{Import: imports},
				&stage.BaseStageOptions{ImageName: "app", TargetPlatform: "linux/amd64"},
			),
		})

		return img
	}

	phaseWithBackendImages := func(infos map[string]*imagePkg.Info) *BuildPhase {
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().
			GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ interface{}, ref string, _ container_backend.GetImageInfoOpts) (*imagePkg.Info, error) {
				return infos[ref], nil
			}).AnyTimes()

		return &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{ContainerBackend: backend}}}
	}

	infoFor := func(ref, repo, digest string) *imagePkg.Info {
		return &imagePkg.Info{Name: ref, Repository: repo, RepoDigest: repo + "@" + digest}
	}

	It("should keep a single entry when the same image is imported several times", func(ctx SpecContext) {
		phase := phaseWithBackendImages(map[string]*imagePkg.Info{
			"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
		})

		resolved, err := phase.resolveImportImages(ctx, imageWithExternalImports(
			"example.org/builder:latest",
			"example.org/builder:latest",
			"example.org/builder:latest",
		))

		Expect(err).To(Succeed())
		Expect(resolved).To(HaveLen(1))
		Expect(resolved[0].imageName).To(Equal("example.org/builder:latest"))
	})

	It("should keep a single entry for different references resolving to the same image", func(ctx SpecContext) {
		phase := phaseWithBackendImages(map[string]*imagePkg.Info{
			"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
			"example.org/builder:v1":     infoFor("example.org/builder:v1", "example.org/builder", "sha256:aaa"),
		})

		resolved, err := phase.resolveImportImages(ctx, imageWithExternalImports(
			"example.org/builder:latest",
			"example.org/builder:v1",
		))

		Expect(err).To(Succeed())
		Expect(resolved).To(HaveLen(1))
	})

	It("should keep every distinct import image", func(ctx SpecContext) {
		phase := phaseWithBackendImages(map[string]*imagePkg.Info{
			"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
			"example.org/assets:latest":  infoFor("example.org/assets:latest", "example.org/assets", "sha256:bbb"),
		})

		resolved, err := phase.resolveImportImages(ctx, imageWithExternalImports(
			"example.org/builder:latest",
			"example.org/assets:latest",
			"example.org/builder:latest",
		))

		Expect(err).To(Succeed())
		Expect(resolved).To(HaveLen(2))
		Expect(resolved[0].imageName).To(Equal("example.org/builder:latest"))
		Expect(resolved[1].imageName).To(Equal("example.org/assets:latest"))
	})
})
