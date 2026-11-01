package build

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("resolveImportImages", func() {
	const targetPlatform = "linux/amd64"

	type importRef struct {
		name     string
		external bool
	}

	external := func(name string) importRef { return importRef{name: name, external: true} }
	internal := func(name string) importRef { return importRef{name: name} }

	imageWithImports := func(refs ...importRef) *image.Image {
		imports := make([]*config.Import, 0, len(refs))
		for _, ref := range refs {
			imports = append(imports, &config.Import{
				Export:        &config.Export{},
				From:          ref.name,
				Before:        string(stage.Install),
				ExternalImage: ref.external,
			})
		}

		img := &image.Image{TargetPlatform: targetPlatform}
		img.SetStages([]stage.Interface{
			stage.GenerateDependenciesBeforeInstallStage(
				&config.StapelImageBase{Import: imports},
				&stage.BaseStageOptions{ImageName: "app", TargetPlatform: targetPlatform},
			),
		})

		return img
	}

	infoFor := func(ref, repo, digest string) *imagePkg.Info {
		return &imagePkg.Info{Name: ref, Repository: repo, RepoDigest: repo + "@" + digest}
	}

	// backendInfos answer external references through the container backend; builtInfos
	// stand for images built by this conveyor and answer internal references.
	newPhase := func(backendInfos, builtInfos map[string]*imagePkg.Info) *BuildPhase {
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().
			GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ any, ref string, _ container_backend.GetImageInfoOpts) (*imagePkg.Info, error) {
				return backendInfos[ref], nil
			}).AnyTimes()

		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		for name, info := range builtInfos {
			builtImg := &image.Image{Name: name, TargetPlatform: targetPlatform}
			builtImg.SetContentTagDesc(&imagePkg.StageDesc{Info: info})
			tree.AppendImageForTests(builtImg)
		}

		return &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{ContainerBackend: backend, imagesTree: tree}}}
	}

	type expectedEntry struct {
		imageName  string
		lookupName string
	}

	ext := func(imageName string) expectedEntry { return expectedEntry{imageName: imageName} }
	built := func(name string) expectedEntry { return expectedEntry{imageName: name, lookupName: name} }

	DescribeTable("keeps one entry per SBOM artifact it would read",
		func(ctx SpecContext, backendInfos, builtInfos map[string]*imagePkg.Info, refs []importRef, expected []expectedEntry) {
			resolved, err := newPhase(backendInfos, builtInfos).resolveImportImages(ctx, imageWithImports(refs...))

			Expect(err).To(Succeed())
			entries := make([]expectedEntry, 0, len(resolved))
			for _, entry := range resolved {
				entries = append(entries, expectedEntry{imageName: entry.imageName, lookupName: entry.lookupName})
			}
			Expect(entries).To(Equal(expected))
		},

		Entry("the same external image imported several times",
			map[string]*imagePkg.Info{
				"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
			}, nil,
			[]importRef{external("example.org/builder:latest"), external("example.org/builder:latest"), external("example.org/builder:latest")},
			[]expectedEntry{ext("example.org/builder:latest")},
		),
		Entry("the same built image imported several times",
			nil, map[string]*imagePkg.Info{
				"builder": infoFor("builder", "example.org/project", "sha256:aaa"),
			},
			[]importRef{internal("builder"), internal("builder")},
			[]expectedEntry{built("builder")},
		),
		Entry("different references resolving to the same image",
			map[string]*imagePkg.Info{
				"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
				"example.org/builder:v1":     infoFor("example.org/builder:v1", "example.org/builder", "sha256:aaa"),
			}, nil,
			[]importRef{external("example.org/builder:latest"), external("example.org/builder:v1")},
			[]expectedEntry{ext("example.org/builder:latest")},
		),
		Entry("a Docker Hub library image written with and without its implicit prefix",
			map[string]*imagePkg.Info{
				"alpine:3":                   infoFor("alpine:3", "alpine", "sha256:aaa"),
				"docker.io/library/alpine:3": infoFor("docker.io/library/alpine:3", "docker.io/library/alpine", "sha256:aaa"),
			}, nil,
			[]importRef{external("alpine:3"), external("docker.io/library/alpine:3")},
			[]expectedEntry{ext("alpine:3")},
		),
		Entry("distinct images, keeping the order of first appearance",
			map[string]*imagePkg.Info{
				"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
				"example.org/assets:latest":  infoFor("example.org/assets:latest", "example.org/assets", "sha256:bbb"),
			}, nil,
			[]importRef{external("example.org/builder:latest"), external("example.org/assets:latest"), external("example.org/builder:latest")},
			[]expectedEntry{ext("example.org/builder:latest"), ext("example.org/assets:latest")},
		),
		Entry("two digests of the same repository",
			map[string]*imagePkg.Info{
				"example.org/builder:v1": infoFor("example.org/builder:v1", "example.org/builder", "sha256:aaa"),
				"example.org/builder:v2": infoFor("example.org/builder:v2", "example.org/builder", "sha256:bbb"),
			}, nil,
			[]importRef{external("example.org/builder:v1"), external("example.org/builder:v2")},
			[]expectedEntry{ext("example.org/builder:v1"), ext("example.org/builder:v2")},
		),
		Entry("the same digest in two repositories",
			map[string]*imagePkg.Info{
				"example.org/builder:latest": infoFor("example.org/builder:latest", "example.org/builder", "sha256:aaa"),
				"mirror.org/builder:latest":  infoFor("mirror.org/builder:latest", "mirror.org/builder", "sha256:aaa"),
			}, nil,
			[]importRef{external("example.org/builder:latest"), external("mirror.org/builder:latest")},
			[]expectedEntry{ext("example.org/builder:latest"), ext("mirror.org/builder:latest")},
		),
		Entry("built images sharing a digest, their SBOM artifacts told apart by name",
			nil, map[string]*imagePkg.Info{
				"backend":  infoFor("backend", "example.org/app", "sha256:aaa"),
				"frontend": infoFor("frontend", "example.org/app", "sha256:aaa"),
			},
			[]importRef{internal("backend"), internal("frontend")},
			[]expectedEntry{built("backend"), built("frontend")},
		),
	)

	// An external source is in the backend only because something pulled it, and the
	// pull belongs to the build of the stage that copies from it: a stage answered from
	// the cache leaves the backend without the image the verification has to read.
	DescribeTable("pulls an external import source the backend does not hold yet",
		func(ctx SpecContext, absent func(ref string) (*imagePkg.Info, error)) {
			const ref = "example.org/builder:latest"
			info := infoFor(ref, "example.org/builder", "sha256:aaa")

			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			var pulled bool
			backend.EXPECT().
				GetImageInfo(gomock.Any(), ref, gomock.Any()).
				DoAndReturn(func(_ any, ref string, _ container_backend.GetImageInfoOpts) (*imagePkg.Info, error) {
					if pulled {
						return info, nil
					}
					return absent(ref)
				}).AnyTimes()
			backend.EXPECT().
				Pull(gomock.Any(), ref, gomock.Any()).
				DoAndReturn(func(_ any, _ string, _ container_backend.PullOpts) error {
					pulled = true
					return nil
				}).Times(1)

			phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{
				ContainerBackend: backend,
				imagesTree:       image.NewImagesTree(nil, image.ImagesTreeOptions{}),
			}}}

			resolved, err := phase.resolveImportImages(ctx, imageWithImports(external(ref)))

			Expect(err).To(Succeed())
			Expect(resolved).To(HaveLen(1))
			Expect(resolved[0].info).To(Equal(info))
		},

		Entry("a backend answering that it holds no such image",
			func(string) (*imagePkg.Info, error) { return nil, nil }),
		Entry("a backend failing to inspect an image it does not hold",
			func(ref string) (*imagePkg.Info, error) { return nil, fmt.Errorf("inspect image %q: not found", ref) }),
	)

	It("leaves an external import source it cannot pull unresolved", func(ctx SpecContext) {
		const ref = "example.org/builder:latest"

		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().
			GetImageInfo(gomock.Any(), ref, gomock.Any()).
			Return(nil, nil).AnyTimes()
		backend.EXPECT().
			Pull(gomock.Any(), ref, gomock.Any()).
			Return(fmt.Errorf("unauthorized")).Times(1)

		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{
			ContainerBackend: backend,
			imagesTree:       image.NewImagesTree(nil, image.ImagesTreeOptions{}),
		}}}

		resolved, err := phase.resolveImportImages(ctx, imageWithImports(external(ref)))

		// A reference nothing answers is not guessed at: the entry carries no image,
		// and the verification of the composition refuses it.
		Expect(err).To(Succeed())
		Expect(resolved).To(BeEmpty())
	})
})
