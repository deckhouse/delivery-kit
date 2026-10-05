package build

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	werfImage "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v3/pkg/sbom/gomod"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("SbomStep", func() {
	Describe("syftScanRequired", func() {
		DescribeTable("should decide whether syft must scan the image",
			func(isStapel bool, catalogers []scanner.Cataloger, expected bool) {
				Expect(syftScanRequired(isStapel, catalogers)).To(Equal(expected))
			},
			Entry("stapel image without packages catalogers", true, nil, false),
			Entry("stapel image with empty catalogers list", true, []scanner.Cataloger{}, false),
			Entry("stapel image with packages catalogers", true, []scanner.Cataloger{{Name: "python-pip-cataloger"}}, true),
			Entry("dockerfile image without catalogers", false, nil, true),
			Entry("dockerfile image with catalogers", false, []scanner.Cataloger{{Name: "python-pip-cataloger"}}, true),
		)
	})

	Describe("prepareGostComponents", func() {
		It("prints the GOST experimental warning at most once per step instance", func() {
			var output bytes.Buffer
			ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&output, &output))

			step := &sbomStep{}
			mergeOpts := cyclonedxutil.MergeOpts{Gost: gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes}}

			Expect(step.prepareGostComponents(ctx, &mergeOpts)).To(Succeed())
			Expect(step.prepareGostComponents(ctx, &mergeOpts)).To(Succeed())
			Expect(step.prepareGostComponents(ctx, &mergeOpts)).To(Succeed())

			Expect(strings.Count(output.String(), "GOST SBOM integration is experimental")).To(Equal(1))
		})
	})

	Describe("GetImageBOM()", func() {
		It("should return error if image info is nil", func(ctx SpecContext) {
			step := &sbomStep{}
			_, err := step.GetImageBOM(ctx, "app", nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("image info is nil"))
		})

		It("should return fatal error if image digest is empty", func(ctx SpecContext) {
			step := &sbomStep{}
			imgInfo := &werfImage.Info{Name: "app:latest"}
			_, err := step.GetImageBOM(ctx, "app", imgInfo)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrSbomNotRequired)).To(BeFalse())
		})
	})

	Describe("BOMPatcher (gomod)", func() {
		DescribeTable("Apply()",
			func(
				ctx context.Context,
				setupGitRepo func(ctx context.Context, repo *mock.MockGitRepo, commit, imageContext string),
			) {
				repo := mock.NewMockGitRepo(gomock.NewController(GinkgoT()))
				commit := "0123456789abcdef0123456789abcdef01234567"
				imageContext := "app"
				setupGitRepo(ctx, repo, commit, imageContext)

				patcher := gomod.NewBOMPatcher(repo, commit, imageContext)
				bom := &cdx.BOM{
					Metadata: &cdx.Metadata{
						Component: &cdx.Component{
							Name: "app",
						},
					},
				}

				res, err := patcher.Apply(ctx, bom)
				Expect(err).ToNot(HaveOccurred())
				Expect(res).ToNot(BeNil())
			},
			Entry(
				"[go.mod]: should skip version resolution when go.mod is missing",
				logging.WithLogger(context.Background()),
				func(ctx context.Context, repo *mock.MockGitRepo, commit, imageContext string) {
					repo.EXPECT().IsCommitFileExist(ctx, commit, filepath.Join(imageContext, "go.mod")).Return(false, nil)
				},
			),
			Entry(
				"[go.mod]: should use tag version when tag matches commit",
				logging.WithLogger(context.Background()),
				func(ctx context.Context, repo *mock.MockGitRepo, commit, imageContext string) {
					goModPath := filepath.Join(imageContext, "go.mod")
					repo.EXPECT().IsCommitFileExist(ctx, commit, goModPath).Return(true, nil)
					repo.EXPECT().ReadCommitFile(ctx, commit, goModPath).Return([]byte("module example.com/app\n"), nil)
					repo.EXPECT().TagsList(ctx).Return([]string{"v1.2.3"}, nil)
					repo.EXPECT().TagCommit(ctx, "v1.2.3").Return(commit, nil)
				},
			),
			Entry(
				"[go.mod]: should fallback to pseudo version when tag mismatch",
				logging.WithLogger(context.Background()),
				func(ctx context.Context, repo *mock.MockGitRepo, commit, imageContext string) {
					goModPath := filepath.Join(imageContext, "go.mod")
					repo.EXPECT().IsCommitFileExist(ctx, commit, goModPath).Return(true, nil)
					repo.EXPECT().ReadCommitFile(ctx, commit, goModPath).Return([]byte("module example.com/app\n"), nil)
					repo.EXPECT().TagsList(ctx).Return([]string{"v1.2.3"}, nil)
					repo.EXPECT().TagCommit(ctx, "v1.2.3").Return("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
				},
			),
		)
	})

	Describe("scanFileBasedPackages", func() {
		makeBOMJSON := func(timestamp string, comps ...cdx.Component) []byte {
			bom := cyclonedxutil.NewBOM()
			bom.Metadata = &cdx.Metadata{
				Timestamp: timestamp,
				Component: &cdx.Component{Type: cdx.ComponentTypeFile, Name: "/scan"},
			}
			list := append([]cdx.Component{}, comps...)
			bom.Components = &list
			data, err := cyclonedxutil.ToJSON(bom)
			Expect(err).To(Succeed())
			return data
		}

		It("scans one dir source per cataloger, unions components, drops source files, keeps syft metadata", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			ctrl := gomock.NewController(GinkgoT())
			mockBackend := mock.NewMockContainerBackend(ctrl)

			imageRef := "app:latest"
			catalogers := []scanner.Cataloger{
				{Name: "go-module-file-cataloger", SourcePaths: []string{"/app/go.mod", "/app/go.sum"}, SourceLang: "Go"},
				{Name: "python-package-cataloger", SourcePaths: []string{"/svc/requirements.txt"}, SourceLang: "Python"},
			}

			mockReader := mock.NewMockImageReader(ctrl)
			mockReader.EXPECT().ReadFile(gomock.Any(), gomock.Any()).Return([]byte("manifest\n"), nil).AnyTimes()
			mockReader.EXPECT().Close(gomock.Any()).Return(nil).AnyTimes()
			mockBackend.EXPECT().
				OpenImageReader(gomock.Any(), imageRef, gomock.Any()).
				Return(mockReader, nil).
				AnyTimes()

			goBOM := makeBOMJSON("2026-01-01T00:00:00Z",
				cdx.Component{BOMRef: "lo", Type: cdx.ComponentTypeLibrary, Name: "github.com/samber/lo", Version: "v1.47.0", PackageURL: "pkg:golang/github.com/samber/lo@v1.47.0"},
				// a PURL-less type=file entry a dir scan emits for the manifest itself
				cdx.Component{BOMRef: "gomod-file", Type: cdx.ComponentTypeFile, Name: "go.mod"},
			)
			pipBOM := makeBOMJSON("2026-02-02T00:00:00Z",
				cdx.Component{BOMRef: "flask", Type: cdx.ComponentTypeLibrary, Name: "flask", Version: "3.0.0", PackageURL: "pkg:pypi/flask@3.0.0"},
			)

			mockBackend.EXPECT().
				GenerateSBOM(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, opts scanner.ScanOptions) ([]byte, error) {
					Expect(opts.Commands).To(HaveLen(1))
					Expect(opts.Commands[0].SourceType).To(Equal(scanner.SourceTypeDir), "each per-directive scan must use a directory source")
					Expect(opts.Commands[0].Catalogers).To(HaveLen(1), "each scan must run exactly one cataloger")
					switch opts.Commands[0].Catalogers[0].Name {
					case "go-module-file-cataloger":
						return goBOM, nil
					case "python-package-cataloger":
						return pipBOM, nil
					default:
						return nil, errors.New("unexpected cataloger: " + opts.Commands[0].Catalogers[0].Name)
					}
				}).
				Times(2)

			step := &sbomStep{containerBackend: mockBackend}
			bom, err := step.scanFileBasedPackages(ctx, &werfImage.Info{Name: imageRef}, scanner.DefaultSyftScanOptions(), catalogers, "")
			Expect(err).To(Succeed())
			Expect(bom).ToNot(BeNil())

			names := []string{}
			for _, c := range *bom.Components {
				names = append(names, c.Name)
			}
			Expect(names).To(ConsistOf("github.com/samber/lo", "flask"), "components from both directives are unioned and the source file is dropped")
			Expect(names).ToNot(ContainElement("go.mod"))

			langsByName := map[string][]string{}
			for i := range *bom.Components {
				comp := &(*bom.Components)[i]
				langsByName[comp.Name] = gost.GetComponentSourceLangs(ctx, comp)
			}
			Expect(langsByName).To(Equal(map[string][]string{
				"github.com/samber/lo": {"Go"},
				"flask":                {"Python"},
			}), "each component carries the source language of the directive that cataloged it")

			Expect(bom.Metadata).ToNot(BeNil())
			Expect(bom.Metadata.Timestamp).To(Equal("2026-01-01T00:00:00Z"), "syft metadata (timestamp) from the first directive is preserved, not discarded")
		})

		It("records the packages each directive declares as dependencies of the scan root", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			ctrl := gomock.NewController(GinkgoT())
			mockBackend := mock.NewMockContainerBackend(ctrl)

			imageRef := "app:latest"
			catalogers := []scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", SourcePaths: []string{"/app/go.mod"}, SourceLang: "Go"},
				{Name: "python-package-cataloger", Ecosystem: string(config.PackagesDirectiveTypePythonPip), Workdir: "/svc", SourcePaths: []string{"/svc/requirements.txt"}, SourceLang: "Python"},
			}

			mockReader := mock.NewMockImageReader(ctrl)
			mockReader.EXPECT().ReadFile(gomock.Any(), "/app/go.mod").Return([]byte("module example.com/app\n\nrequire (\n\tgithub.com/samber/lo v1.47.0\n\tgolang.org/x/text v0.3.0 // indirect\n)\n"), nil)
			mockReader.EXPECT().ReadFile(gomock.Any(), "/svc/requirements.txt").Return([]byte("flask==3.0.0\n"), nil)
			mockReader.EXPECT().Close(gomock.Any()).Return(nil).AnyTimes()
			mockBackend.EXPECT().OpenImageReader(gomock.Any(), imageRef, gomock.Any()).Return(mockReader, nil).AnyTimes()

			scanRoot := func(ref string, comps ...cdx.Component) []byte {
				bom := cyclonedxutil.NewBOM()
				bom.Metadata = &cdx.Metadata{Component: &cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeFile, Name: "/scan"}}
				bom.Components = &comps
				data, err := cyclonedxutil.ToJSON(bom)
				Expect(err).To(Succeed())
				return data
			}
			goBOM := scanRoot("scan-go",
				cdx.Component{BOMRef: "lo", Type: cdx.ComponentTypeLibrary, Name: "github.com/samber/lo", Version: "v1.47.0", PackageURL: "pkg:golang/github.com/samber/lo@v1.47.0"},
				cdx.Component{BOMRef: "text", Type: cdx.ComponentTypeLibrary, Name: "golang.org/x/text", Version: "v0.3.0", PackageURL: "pkg:golang/golang.org/x/text@v0.3.0"},
			)
			pipBOM := scanRoot("scan-pip",
				cdx.Component{BOMRef: "flask", Type: cdx.ComponentTypeLibrary, Name: "flask", Version: "3.0.0", PackageURL: "pkg:pypi/flask@3.0.0"},
				cdx.Component{BOMRef: "jinja", Type: cdx.ComponentTypeLibrary, Name: "jinja2", Version: "3.1.0", PackageURL: "pkg:pypi/jinja2@3.1.0"},
			)

			mockBackend.EXPECT().
				GenerateSBOM(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, opts scanner.ScanOptions) ([]byte, error) {
					if opts.Commands[0].Catalogers[0].Name == "go-module-file-cataloger" {
						return goBOM, nil
					}
					return pipBOM, nil
				}).
				Times(2)
			mockBackend.EXPECT().
				RunCommandInImage(gomock.Any(), imageRef, gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, opts container_backend.RunCommandInImageOpts) ([]byte, error) {
					Expect(opts.Command).To(Equal([]string{"go", "mod", "graph"}))
					Expect(opts.Workdir).To(Equal("/app"))
					Expect(opts.Env).To(ContainElements("GOPROXY=off", "GOFLAGS=-mod=mod"))
					return []byte("example.com/app github.com/samber/lo@v1.47.0\ngithub.com/samber/lo@v1.47.0 golang.org/x/text@v0.3.0\n"), nil
				}).
				Times(1)

			step := &sbomStep{containerBackend: mockBackend}
			bom, err := step.scanFileBasedPackages(ctx, &werfImage.Info{Name: imageRef}, scanner.DefaultSyftScanOptions(), catalogers, "")
			Expect(err).To(Succeed())

			Expect(bom.Metadata.Component.BOMRef).To(Equal("scan-go"), "the root of the first directive scan is the root of the union")
			refOf := func(name string) string {
				for _, comp := range *bom.Components {
					if comp.Name == name {
						return comp.BOMRef
					}
				}
				Fail("no component " + name)
				return ""
			}
			Expect(*bom.Dependencies).To(ConsistOf(
				cdx.Dependency{Ref: "scan-go", Dependencies: &[]string{refOf("flask"), refOf("github.com/samber/lo")}},
				cdx.Dependency{Ref: refOf("github.com/samber/lo"), Dependencies: &[]string{refOf("golang.org/x/text")}},
			), "the declared packages of every directive hang off one root; the indirect module and the transitive pip package do not; Go modules carry their graph")
		})

		It("keeps the SBOM when the Go module graph cannot be read from the image", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			ctrl := gomock.NewController(GinkgoT())
			mockBackend := mock.NewMockContainerBackend(ctrl)

			mockReader := mock.NewMockImageReader(ctrl)
			mockReader.EXPECT().ReadFile(gomock.Any(), "/app/go.mod").Return([]byte("module example.com/app\n\nrequire github.com/samber/lo v1.47.0\n"), nil)
			mockReader.EXPECT().Close(gomock.Any()).Return(nil).AnyTimes()
			mockBackend.EXPECT().OpenImageReader(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockReader, nil)
			scanBOM := cyclonedxutil.NewBOM()
			scanBOM.Metadata = &cdx.Metadata{Component: &cdx.Component{BOMRef: "scan-go", Type: cdx.ComponentTypeFile, Name: "/scan"}}
			scanBOM.Components = &[]cdx.Component{
				{BOMRef: "lo", Type: cdx.ComponentTypeLibrary, Name: "github.com/samber/lo", Version: "v1.47.0", PackageURL: "pkg:golang/github.com/samber/lo@v1.47.0"},
			}
			scanJSON, err := cyclonedxutil.ToJSON(scanBOM)
			Expect(err).To(Succeed())
			mockBackend.EXPECT().GenerateSBOM(gomock.Any(), gomock.Any()).Return(scanJSON, nil)
			mockBackend.EXPECT().
				RunCommandInImage(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, opts container_backend.RunCommandInImageOpts) ([]byte, error) {
					Expect(opts.Command[0]).To(Equal("/usr/local/go/bin/go"), "the manager the directive names runs the graph")
					Expect(opts.Env[len(opts.Env)-2:]).To(Equal([]string{"GOPROXY=off", "GOTOOLCHAIN=local"}), "the offline settings win over the directive environment")
					Expect(opts.Env).To(ContainElement("GOPROXY=https://proxy.example.com"))
					return nil, errors.New("exec: go: not found")
				})

			step := &sbomStep{containerBackend: mockBackend}
			bom, err := step.scanFileBasedPackages(ctx, &werfImage.Info{Name: "app:latest"}, scanner.DefaultSyftScanOptions(), []scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", Manager: "/usr/local/go/bin/go", Env: map[string]string{"GOPROXY": "https://proxy.example.com"}, SourcePaths: []string{"/app/go.mod"}},
			}, "")
			Expect(err).To(Succeed())
			Expect(*bom.Components).To(HaveLen(1))
			Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "scan-go", Dependencies: &[]string{(*bom.Components)[0].BOMRef}}}), "the root edge stays; only the module graph is missing")
		})

		It("keeps the SBOM without a declaration when the spec of a directive cannot be read", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			ctrl := gomock.NewController(GinkgoT())
			mockBackend := mock.NewMockContainerBackend(ctrl)

			mockReader := mock.NewMockImageReader(ctrl)
			mockReader.EXPECT().ReadFile(gomock.Any(), "/app/go.mod").Return([]byte("require (\n"), nil)
			mockReader.EXPECT().Close(gomock.Any()).Return(nil).AnyTimes()
			mockBackend.EXPECT().OpenImageReader(gomock.Any(), gomock.Any(), gomock.Any()).Return(mockReader, nil)
			scanBOM := cyclonedxutil.NewBOM()
			scanBOM.Metadata = &cdx.Metadata{Component: &cdx.Component{BOMRef: "scan-go", Type: cdx.ComponentTypeFile, Name: "/scan"}}
			scanBOM.Components = &[]cdx.Component{
				{BOMRef: "lo", Type: cdx.ComponentTypeLibrary, Name: "github.com/samber/lo", Version: "v1.47.0", PackageURL: "pkg:golang/github.com/samber/lo@v1.47.0"},
			}
			scanJSON, err := cyclonedxutil.ToJSON(scanBOM)
			Expect(err).To(Succeed())
			mockBackend.EXPECT().GenerateSBOM(gomock.Any(), gomock.Any()).Return(scanJSON, nil)
			mockBackend.EXPECT().RunCommandInImage(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("example.com/app github.com/samber/lo@v1.47.0\n"), nil)

			step := &sbomStep{containerBackend: mockBackend}
			bom, err := step.scanFileBasedPackages(ctx, &werfImage.Info{Name: "app:latest"}, scanner.DefaultSyftScanOptions(), []scanner.Cataloger{
				{Name: "go-module-file-cataloger", Ecosystem: string(config.PackagesDirectiveTypeGoMod), Workdir: "/app", SourcePaths: []string{"/app/go.mod"}},
			}, "")
			Expect(err).To(Succeed())
			Expect(*bom.Components).To(HaveLen(1))
			Expect(bom.Dependencies).To(BeNil(), "no declaration and no module edges: the single module has no graph of its own")
		})
	})

	Describe("restoreImageMetadata", func() {
		stageDesc := &werfImage.StageDesc{Info: &werfImage.Info{Repository: "example.com/ns/app", Tag: "v1", RepoDigest: "example.com/ns/app@sha256:abc"}}
		expectedRoot := "pkg:oci/app@sha256:abc?repository_url=example.com%2Fns%2Fapp&tag=v1"

		expectContainerComponent := func(bom *cdx.BOM) {
			Expect(bom.Metadata).ToNot(BeNil())
			Expect(bom.Metadata.Component).ToNot(BeNil())
			Expect(bom.Metadata.Component.Type).To(Equal(cdx.ComponentTypeContainer))
			Expect(bom.Metadata.Component.Name).To(Equal("example.com/ns/app"))
			Expect(bom.Metadata.Component.Version).To(Equal("v1"))
			Expect(bom.Metadata.Component.BOMRef).To(Equal(expectedRoot))
			Expect(bom.Metadata.Component.PackageURL).To(Equal(expectedRoot))
		}

		It("allocates metadata and stamps a timestamp when the BOM has none", func() {
			bom := &cdx.BOM{}

			restoreImageMetadata(bom, stageDesc)

			expectContainerComponent(bom)
			Expect(bom.Metadata.Timestamp).ToNot(BeEmpty(), "a per-image SBOM must carry a timestamp for downstream validators")
		})

		It("keeps syft's tools and timestamp and replaces only the scan-directory component", func() {
			bom := &cdx.BOM{
				Metadata: &cdx.Metadata{
					Timestamp: "2020-01-02T03:04:05Z",
					Tools:     &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "syft", Version: "1.45.1"}}},
					Component: &cdx.Component{Type: cdx.ComponentTypeFile, Name: "/scan"},
				},
			}

			restoreImageMetadata(bom, stageDesc)

			expectContainerComponent(bom)
			Expect(bom.Metadata.Timestamp).To(Equal("2020-01-02T03:04:05Z"), "syft's own timestamp must survive")
			Expect(bom.Metadata.Tools).ToNot(BeNil())
			Expect(bom.Metadata.Tools.Components).ToNot(BeNil())
			Expect(*bom.Metadata.Tools.Components).To(HaveLen(2))
			Expect((*bom.Metadata.Tools.Components)[0].Name).To(Equal("syft"), "syft tools provenance must survive")
			Expect((*bom.Metadata.Tools.Components)[1].Name).To(Equal("werf"), "werf records itself next to the scanner")
			Expect(cyclonedxutil.HasWerfTool(bom)).To(BeTrue())
		})

		It("moves the edges sourced at the scan directory onto the image", func() {
			bom := &cdx.BOM{
				Metadata:   &cdx.Metadata{Component: &cdx.Component{BOMRef: "scan", Type: cdx.ComponentTypeFile, Name: "/scan"}},
				Components: &[]cdx.Component{{BOMRef: "lo"}, {BOMRef: "text"}},
				Dependencies: &[]cdx.Dependency{
					{Ref: "scan", Dependencies: &[]string{"lo"}},
					{Ref: "lo", Dependencies: &[]string{"text"}},
				},
			}

			restoreImageMetadata(bom, stageDesc)

			expectContainerComponent(bom)
			Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{
				{Ref: expectedRoot, Dependencies: &[]string{"lo"}},
				{Ref: "lo", Dependencies: &[]string{"text"}},
			}))
		})

		It("leaves the root without a ref and the edges untouched when the image has no digest yet", func() {
			bom := &cdx.BOM{
				Metadata:     &cdx.Metadata{Component: &cdx.Component{BOMRef: "scan", Type: cdx.ComponentTypeFile, Name: "/scan"}},
				Components:   &[]cdx.Component{{BOMRef: "lo"}},
				Dependencies: &[]cdx.Dependency{{Ref: "scan", Dependencies: &[]string{"lo"}}},
			}

			restoreImageMetadata(bom, &werfImage.StageDesc{Info: &werfImage.Info{Repository: "example.com/app", Tag: "v1"}})

			Expect(bom.Metadata.Component.BOMRef).To(BeEmpty())
			Expect(bom.Metadata.Component.PackageURL).To(BeEmpty())
			Expect(*bom.Dependencies).To(Equal([]cdx.Dependency{{Ref: "scan", Dependencies: &[]string{"lo"}}}), "no rewrite to an empty ref")
		})
	})

	Describe("isTrustedBuilderImage()", func() {
		DescribeTable("should detect trusted builder images",
			func(labels map[string]string, expected bool) {
				Expect(isTrustedBuilderImage(labels)).To(Equal(expected))
			},
			Entry("nil labels", nil, false),
			Entry("empty labels", map[string]string{}, false),
			Entry("label set to false", map[string]string{werfImage.DeckhouseInternalBuilderLabel: "false"}, false),
			Entry("label set to true", map[string]string{werfImage.DeckhouseInternalBuilderLabel: "true"}, true),
			Entry("other labels without builder", map[string]string{"foo": "bar", "baz": "qux"}, false),
			Entry("other labels with builder true", map[string]string{"foo": "bar", werfImage.DeckhouseInternalBuilderLabel: "true", "baz": "qux"}, true),
		)
	})

	Describe("GetImageBOM() with trusted builder image", func() {
		It("should return hard error for builder image from different namespace", func(ctx SpecContext) {
			step := &sbomStep{}

			imageInfo := &werfImage.Info{
				Name:       "docker.io/namespace/repo:builder-tag",
				Repository: "docker.io/namespace/repo",
				Labels: map[string]string{
					werfImage.DeckhouseInternalBuilderLabel: "true",
				},
			}

			_, err := step.GetImageBOM(ctx, "builder-image", imageInfo)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrSbomNotRequired)).To(BeFalse())
			Expect(err.Error()).To(ContainSubstring("the image is a builder image but SBOM is required"))
		})

		It("should return ErrSbomNotRequired for golang builder image from container-factory", func(ctx SpecContext) {
			step := &sbomStep{}

			imageInfo := &werfImage.Info{
				Name:       "registry.deckhouse.io/container-factory/builder/golang-alpine:1.25",
				Repository: "registry.deckhouse.io/container-factory/builder/golang-alpine",
				Labels: map[string]string{
					werfImage.DeckhouseInternalBuilderLabel: "true",
				},
			}

			_, err := step.GetImageBOM(logging.WithLogger(ctx), "builder-image", imageInfo)
			Expect(err).To(MatchError(ErrSbomNotRequired))
		})

		It("should return ErrSbomNotRequired for alpine builder image from container-factory", func(ctx SpecContext) {
			step := &sbomStep{}

			imageInfo := &werfImage.Info{
				Name:       "registry.deckhouse.io/container-factory/builder/alpine:3.22",
				Repository: "registry.deckhouse.io/container-factory/builder/alpine",
				Labels: map[string]string{
					werfImage.DeckhouseInternalBuilderLabel: "true",
				},
			}

			_, err := step.GetImageBOM(ctx, "builder-image", imageInfo)
			Expect(err).To(MatchError(ErrSbomNotRequired))
		})

		It("should return hard error for other builder image from container-factory", func(ctx SpecContext) {
			step := &sbomStep{}

			imageInfo := &werfImage.Info{
				Name:       "registry.deckhouse.io/container-factory/builder/scratch",
				Repository: "registry.deckhouse.io/container-factory/builder/scratch",
				Labels: map[string]string{
					werfImage.DeckhouseInternalBuilderLabel: "true",
				},
			}

			_, err := step.GetImageBOM(ctx, "builder-image", imageInfo)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrSbomNotRequired)).To(BeFalse())
			Expect(err.Error()).To(ContainSubstring("the image is a builder image but SBOM is required"))
		})

		It("should return actionable error for non-builder image when SBOM pull fails", func(ctx SpecContext) {
			step := &sbomStep{}

			imageInfo := &werfImage.Info{
				Name:       "docker.io/namespace/repo:some-tag",
				Repository: "docker.io/namespace/repo",
				Labels:     map[string]string{},
			}

			_, err := step.GetImageBOM(ctx, "app", imageInfo)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrSbomNotRequired)).To(BeFalse())
			Expect(err.Error()).NotTo(ContainSubstring(werfImage.DeckhouseInternalBuilderLabel))
			Expect(err.Error()).To(ContainSubstring("rebuild it with SBOM generation enabled"))
		})
	})
})
