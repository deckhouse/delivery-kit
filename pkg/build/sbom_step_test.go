package build

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/container_backend/filter"
	"github.com/werf/werf/v2/pkg/container_backend/label"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/logging"
	"github.com/werf/werf/v2/pkg/sbom"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("SbomStep", func() {
	DescribeTable("Converge()",
		func(
			ctx context.Context,
			isLocalStorage bool,
			setupMocks func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				stagesStorage *mock.MockStagesStorage,
				stageDesc *image.StageDesc,
				scanOpts scanner.ScanOptions,
				sbomImgLabels label.LabelList,
				imgFilters []util.Pair[string, string],
			),
		) {
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			stagesStorage := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))

			step := newSbomStep(backend, stagesStorage)
			step.isLocalStorage = isLocalStorage

			ctx = logging.WithLogger(ctx)
			stageDesc := &image.StageDesc{
				Info: &image.Info{
					Name: "docker.io/namespace/repo:e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff-1747987463184",
					Labels: map[string]string{
						image.WerfLabel:                   "werf-test-app",
						image.WerfProjectRepoCommitLabel:  "fdf911003d06d63460172a0e663bf492cb9b8160",
						image.WerfStageContentDigestLabel: "7072c9c90d5b76981e4ef55ab07c2d935039b3eb73570354aaf4c2da",
						image.WerfVersionLabel:            "dev",
					},
				},
			}
			scanOpts := scanner.DefaultSyftScanOptions()

			sbomBaseImgLabels := step.prepareSbomBaseLabels(ctx, stageDesc.Info.Labels, scanOpts)
			imgFilters := filter.NewFilterListFromLabelList(sbomBaseImgLabels).ToPairs()

			sbomImgLabels := step.prepareSbomLabels(ctx, stageDesc.Info.Labels, scanOpts)
			setupMocks(ctx, backend, stagesStorage, stageDesc, scanOpts, sbomImgLabels, imgFilters)

			Expect(step.Converge(ctx, "some-name", stageDesc, scanOpts)).To(Succeed())
		},
		Entry(
			"[local storage]: should not scan source image if sbom image is already exist",
			true,
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				stagesStorage *mock.MockStagesStorage,
				stageDesc *image.StageDesc,
				scanOpts scanner.ScanOptions,
				sbomImgLabels label.LabelList,
				imgFilters []util.Pair[string, string],
			) {
				backend.EXPECT().Images(ctx, container_backend.ImagesOptions{Filters: imgFilters}).Return(image.ImagesList{
					{RepoTags: []string{"namespace/repo:e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff-1747987463184-sbom"}},
				}, nil)
			},
		),
		Entry(
			"[local storage]: should scan source image if sbom image is not exist",
			true,
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				stagesStorage *mock.MockStagesStorage,
				stageDesc *image.StageDesc,
				scanOpts scanner.ScanOptions,
				sbomImgLabels label.LabelList,
				imgFilters []util.Pair[string, string],
			) {
				backend.EXPECT().Images(ctx, container_backend.ImagesOptions{Filters: imgFilters}).Return(image.ImagesList{}, nil)

				tmpImgId := "some id"
				backend.EXPECT().GenerateSBOM(ctx, scanOpts, sbomImgLabels.ToStringSlice()).Return(tmpImgId, nil)
				backend.EXPECT().Tag(ctx, tmpImgId, sbom.ImageName(stageDesc.Info.Name), container_backend.TagOpts{}).Return(nil)
			},
		),
		Entry(
			"[remote storage]: should push sbom source image if it exist locally",
			false,
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				stagesStorage *mock.MockStagesStorage,
				stageDesc *image.StageDesc,
				scanOpts scanner.ScanOptions,
				sbomImgLabels label.LabelList,
				imgFilters []util.Pair[string, string],
			) {
				backend.EXPECT().Images(ctx, container_backend.ImagesOptions{Filters: imgFilters}).Return(image.ImagesList{
					{RepoTags: []string{"namespace/repo:e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff-1747987463184-sbom"}},
				}, nil)
				stagesStorage.EXPECT().PushIfNotExistSbomImage(ctx, sbom.ImageName(stageDesc.Info.Name)).Return(true, nil)
			},
		),
		Entry(
			"[remote storage]: should not scan if sbom image is pulled from registry",
			false,
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				stagesStorage *mock.MockStagesStorage,
				stageDesc *image.StageDesc,
				scanOpts scanner.ScanOptions,
				sbomImgLabels label.LabelList,
				imgFilters []util.Pair[string, string],
			) {
				backend.EXPECT().Images(ctx, container_backend.ImagesOptions{Filters: imgFilters}).Return(image.ImagesList{}, nil)
				stagesStorage.EXPECT().PullIfExistSbomImage(ctx, sbom.ImageName(stageDesc.Info.Name)).Return(true, nil)
			},
		),
		Entry(
			"[remote storage]: should scan source image if sbom image is not pulled from registry and push generated sbom image into registry",
			false,
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				stagesStorage *mock.MockStagesStorage,
				stageDesc *image.StageDesc,
				scanOpts scanner.ScanOptions,
				sbomImgLabels label.LabelList,
				imgFilters []util.Pair[string, string],
			) {
				backend.EXPECT().Images(ctx, container_backend.ImagesOptions{Filters: imgFilters}).Return(image.ImagesList{}, nil)
				stagesStorage.EXPECT().PullIfExistSbomImage(ctx, sbom.ImageName(stageDesc.Info.Name)).Return(false, nil)

				backend.EXPECT().Pull(ctx, stageDesc.Info.Name, container_backend.PullOpts{}).Return(nil)

				tmpImgId := "some id"
				backend.EXPECT().GenerateSBOM(ctx, scanOpts, sbomImgLabels.ToStringSlice()).Return(tmpImgId, nil)
				backend.EXPECT().Tag(ctx, tmpImgId, sbom.ImageName(stageDesc.Info.Name), container_backend.TagOpts{}).Return(nil)

				stagesStorage.EXPECT().PushIfNotExistSbomImage(ctx, sbom.ImageName(stageDesc.Info.Name)).Return(true, nil)
			},
		),
	)

	DescribeTable("pullImageSbom()",
		func(
			ctx context.Context,
			baseImageInfo *image.Info,
			expectError bool,
			expectedErrorMsg string,
			setupMocks func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				baseImageInfo *image.Info,
			),
		) {
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			stagesStorage := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))

			step := newSbomStep(backend, stagesStorage)

			ctx = logging.WithLogger(ctx)

			setupMocks(ctx, backend, baseImageInfo)

			_, err := step.pullImageSbom(ctx, "some-name", baseImageInfo)
			if expectError {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrorMsg))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		},
		Entry(
			"should fail if sbom not found in registry",
			context.Background(),
			&image.Info{
				Name:       "docker.io/namespace/repo:e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff-1747987463184",
				Repository: "docker.io/namespace/repo",
				Labels: map[string]string{
					image.WerfStageContentDigestLabel: "e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff",
				},
			},
			true,
			"SBOM for image",
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				baseImageInfo *image.Info,
			) {
				_, tag := image.ParseRepositoryAndTag(baseImageInfo.Name)
				sbomImageName := sbom.BaseImageSbomName(baseImageInfo.Repository, tag)
				backend.EXPECT().GetImageInfo(ctx, sbomImageName, container_backend.GetImageInfoOpts{}).Return(nil, nil)
				backend.EXPECT().Pull(ctx, sbomImageName, container_backend.PullOpts{}).Return(fmt.Errorf("not found"))
			},
		),
		Entry(
			"should fail if no werf labels available",
			context.Background(),
			&image.Info{
				Name:       "ubuntu:22.04",
				Repository: "ubuntu",
				Labels:     map[string]string{},
			},
			true,
			"required werf stage content digest label is missing",
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				baseImageInfo *image.Info,
			) {
				// No mocks needed - should fail before any backend calls
			},
		),
	)

	DescribeTable("pullImageSbom() with local storage",
		func(
			ctx context.Context,
			baseImageInfo *image.Info,
			expectError bool,
			expectedErrorMsg string,
			setupMocks func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				baseImageInfo *image.Info,
			),
		) {
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			stagesStorage := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))

			step := &sbomStep{
				containerBackend: backend,
				stagesStorage:    stagesStorage,
				isLocalStorage:   true,
			}

			ctx = logging.WithLogger(ctx)

			setupMocks(ctx, backend, baseImageInfo)

			_, err := step.pullImageSbom(ctx, "some-name", baseImageInfo)
			if expectError {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrorMsg))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		},
		Entry(
			"should fail if sbom not found locally (no pull for local storage)",
			context.Background(),
			&image.Info{
				Name:       "docker.io/namespace/repo:e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff-1747987463184",
				Repository: "docker.io/namespace/repo",
				Labels: map[string]string{
					image.WerfStageContentDigestLabel: "e5c6ebcd2718ccfe74d01069a0d758e03d5a2554155ccdc01be0daff",
				},
			},
			true,
			"not found locally",
			func(
				ctx context.Context,
				backend *mock.MockContainerBackend,
				baseImageInfo *image.Info,
			) {
				_, tag := image.ParseRepositoryAndTag(baseImageInfo.Name)
				sbomImageName := sbom.BaseImageSbomName(baseImageInfo.Repository, tag)
				backend.EXPECT().GetImageInfo(ctx, sbomImageName, container_backend.GetImageInfoOpts{}).Return(nil, nil)
			},
		),
	)

	DescribeTable("GetImageBOM()",
		func(
			ctx context.Context,
			imageRef string,
			imageInfo *image.Info,
			expectError bool,
			expectedErrorMsg string,
			expectEmptyBOM bool,
		) {
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			stagesStorage := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))

			step := newSbomStep(backend, stagesStorage)

			ctx = logging.WithLogger(ctx)

			bom, err := step.GetImageBOM(ctx, "some-name", imageRef, imageInfo)
			if expectError {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrorMsg))
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(bom).ToNot(BeNil())
				if expectEmptyBOM {
					Expect(bom.Components).ToNot(BeNil())
					Expect(*bom.Components).To(BeEmpty())
				}
			}
		},
		Entry(
			"should return empty BOM for scratch image",
			context.Background(),
			"registry.werf.io/werf/scratch",
			nil,
			false,
			"",
			true,
		),
		Entry(
			"should return empty BOM for scratch image with tag",
			context.Background(),
			"registry.werf.io/werf/scratch:v1.0",
			nil,
			false,
			"",
			true,
		),
		Entry(
			"should fail if imageInfo is nil for non-scratch image",
			context.Background(),
			"ubuntu:22.04",
			nil,
			true,
			"image info not available",
			false,
		),
	)
})
