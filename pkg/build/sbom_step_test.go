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
	werfImage "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/logging"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v2/pkg/sbom/gomod"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
	"github.com/werf/werf/v2/test/mock"
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
				{Name: "go-module-file-cataloger", SourcePaths: []string{"/app/go.mod", "/app/go.sum"}},
				{Name: "python-package-cataloger", SourcePaths: []string{"/svc/requirements.txt"}},
			}

			mockBackend.EXPECT().
				ReadFileFromImage(gomock.Any(), imageRef, gomock.Any(), gomock.Any()).
				Return([]byte("manifest\n"), nil).
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
			bom, err := step.scanFileBasedPackages(ctx, imageRef, scanner.DefaultSyftScanOptions(), catalogers, "")
			Expect(err).To(Succeed())
			Expect(bom).ToNot(BeNil())

			names := []string{}
			for _, c := range *bom.Components {
				names = append(names, c.Name)
			}
			Expect(names).To(ConsistOf("github.com/samber/lo", "flask"), "components from both directives are unioned and the source file is dropped")
			Expect(names).ToNot(ContainElement("go.mod"))

			Expect(bom.Metadata).ToNot(BeNil())
			Expect(bom.Metadata.Timestamp).To(Equal("2026-01-01T00:00:00Z"), "syft metadata (timestamp) from the first directive is preserved, not discarded")
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
