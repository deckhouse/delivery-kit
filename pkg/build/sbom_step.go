package build

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/container_backend/filter"
	"github.com/werf/werf/v2/pkg/container_backend/label"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/sbom"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
	"github.com/werf/werf/v2/pkg/storage"
)

type sbomStep struct {
	containerBackend container_backend.ContainerBackend
	stagesStorage    storage.StagesStorage
	isLocalStorage   bool
}

func newSbomStep(
	backend container_backend.ContainerBackend,
	stagesStorage storage.StagesStorage,
) *sbomStep {
	_, isLocalStorage := stagesStorage.(*storage.LocalStagesStorage)

	return &sbomStep{
		containerBackend: backend,
		stagesStorage:    stagesStorage,
		isLocalStorage:   isLocalStorage,
	}
}

func (step *sbomStep) ConvergeWithMerge(ctx context.Context, werfImgName string, stageDesc *image.StageDesc, scanOpts scanner.ScanOptions, mergeOpts sbom.MergeOpts) error {
	sourceImageName := stageDesc.Info.Name
	sbomImageName := sbom.ImageName(sourceImageName)

	scanOpts.Commands[0].SourcePath = sourceImageName

	sbomBaseImgLabels := step.prepareSbomBaseLabelsWithMerge(ctx, stageDesc.Info.Labels, scanOpts, mergeOpts)
	sbomImgLabels := step.prepareSbomLabelsWithMerge(ctx, stageDesc.Info.Labels, scanOpts, mergeOpts)

	_, ok, err := step.findSbomImageLocally(ctx, sbomBaseImgLabels, sbomImageName)
	if err != nil {
		return err
	}

	if step.isLocalStorage {
		if ok {
			logboek.Context(ctx).Default().LogF("image %s: Use previously generated SBOM from local backend storage\n", werfImgName)
			return nil
		}
	} else {
		if ok {
			if _, err = step.stagesStorage.PushIfNotExistSbomImage(ctx, sbomImageName); err != nil {
				return fmt.Errorf("unable to push sbom image: %q: %w", sbomImageName, err)
			}
			return nil
		} else {
			if pulled, err := step.stagesStorage.PullIfExistSbomImage(ctx, sbomImageName); err != nil {
				return fmt.Errorf("unable to pull sbom image: %q: %w", sbomImageName, err)
			} else if pulled {
				logboek.Context(ctx).Default().LogF("image %s: Use previously generated SBOM from container registry\n", werfImgName)
				return nil
			}
		}
	}

	if !step.isLocalStorage {
		if err := step.containerBackend.Pull(ctx, sourceImageName, container_backend.PullOpts{}); err != nil {
			return fmt.Errorf("unable to pull %q: %w", sourceImageName, err)
		}
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: SBOM processing", werfImgName).DoError(func() error {
		tmpImgId, err := step.containerBackend.GenerateSBOM(ctx, scanOpts, nil)
		if err != nil {
			return fmt.Errorf("unable to scan image: %w", err)
		}

		targetBOM, err := step.extractBOM(ctx, tmpImgId)
		if rmErr := step.containerBackend.Rmi(ctx, tmpImgId, container_backend.RmiOpts{Force: true}); rmErr != nil {
			logboek.Context(ctx).Warn().LogF("unable to remove temp image %q: %s\n", tmpImgId, rmErr)
		}
		if err != nil {
			return fmt.Errorf("unable to extract scanned BOM: %w", err)
		}

		resultBOM := targetBOM
		if !mergeOpts.IsEmpty() {
			resultBOM = sbom.MergeBOMs(targetBOM, mergeOpts)
		}

		sbomImgId, err := step.buildSbomImage(ctx, resultBOM, scanOpts, sbomImgLabels.ToStringSlice())
		if err != nil {
			return err
		}

		if err = step.containerBackend.Tag(ctx, sbomImgId, sbomImageName, container_backend.TagOpts{}); err != nil {
			return fmt.Errorf("unable to tag sbom image: %w", err)
		}

		if !step.isLocalStorage {
			if _, err := step.stagesStorage.PushIfNotExistSbomImage(ctx, sbomImageName); err != nil {
				return fmt.Errorf("unable to push sbom image: %q: %w", sbomImageName, err)
			}
		}

		return nil
	})
}

func (step *sbomStep) extractBOM(ctx context.Context, imageId string) (*cdx.BOM, error) {
	opener := func() (io.ReadCloser, error) {
		return step.containerBackend.SaveImageToStream(ctx, imageId)
	}
	return sbom.ExtractBOMFromImage(opener)
}

func (step *sbomStep) buildSbomImage(ctx context.Context, bom *cdx.BOM, scanOpts scanner.ScanOptions, labels []string) (string, error) {
	wt, err := scanner.PrepareWorkingTreeForBOM(ctx, bom, scanOpts)
	if err != nil {
		return "", err
	}
	defer wt.Cleanup(ctx)

	billNames := scanner.BillNamesFromCommands(scanOpts.Commands)
	contextAddFiles := make([]string, 0, len(billNames)+1)
	for _, billName := range billNames {
		contextAddFiles = append(contextAddFiles, filepath.Join(wt.BillsDir(), billName))
	}
	contextAddFiles = append(contextAddFiles, wt.Containerfile())

	archive := container_backend.NewSbomContextArchiver(wt.RootDir())
	if err := archive.Create(ctx, container_backend.BuildContextArchiveCreateOptions{
		DockerfileRelToContextPath: wt.Containerfile(),
		ContextAddFiles:            contextAddFiles,
	}); err != nil {
		return "", fmt.Errorf("unable to create build context: %w", err)
	}

	imgId, err := step.containerBackend.BuildDockerfile(ctx, wt.ContainerfileContent(), container_backend.BuildDockerfileOpts{
		DockerfileCtxRelPath: wt.Containerfile(),
		BuildContextArchive:  archive,
		Labels:               labels,
	})
	if err != nil {
		return "", fmt.Errorf("unable to build SBOM image: %w", err)
	}

	return imgId, nil
}

func (step *sbomStep) prepareSbomBaseLabelsWithMerge(_ context.Context, srcImgLabels map[string]string, scanOpts scanner.ScanOptions, mergeOpts sbom.MergeOpts) label.LabelList {
	checksum := scanOpts.Checksum()
	if mc := mergeOpts.Checksum(); mc != "" {
		checksum += "-" + mc
	}

	return label.LabelList{
		label.NewLabel(image.WerfLabel, srcImgLabels[image.WerfLabel]),
		label.NewLabel(image.WerfProjectRepoCommitLabel, srcImgLabels[image.WerfProjectRepoCommitLabel]),
		label.NewLabel(image.WerfStageContentDigestLabel, srcImgLabels[image.WerfStageContentDigestLabel]),
		label.NewLabel(image.WerfSbomLabel, checksum),
	}
}

func (step *sbomStep) prepareSbomLabelsWithMerge(ctx context.Context, srcImgLabels map[string]string, scanOpts scanner.ScanOptions, mergeOpts sbom.MergeOpts) label.LabelList {
	list := step.prepareSbomBaseLabelsWithMerge(ctx, srcImgLabels, scanOpts, mergeOpts)
	list.Add(label.NewLabel(image.WerfVersionLabel, srcImgLabels[image.WerfVersionLabel]))
	return list
}

func (step *sbomStep) findSbomImageLocally(ctx context.Context, sbomBaseImgLabels label.LabelList, sbomImgName string) (image.Summary, bool, error) {
	sbomImgList, err := step.containerBackend.Images(ctx, container_backend.ImagesOptions{
		Filters: filter.NewFilterListFromLabelList(sbomBaseImgLabels).ToPairs(),
	})
	if err != nil {
		return image.Summary{}, false, fmt.Errorf("unable to list sbom images: %w", err)
	}

	_, sbomTag := image.ParseRepositoryAndTag(sbomImgName)

	img, ok := lo.Find(sbomImgList, func(img image.Summary) bool {
		return slices.ContainsFunc(img.RepoTags, func(repoTag string) bool {
			_, imgTag := image.ParseRepositoryAndTag(repoTag)
			// TODO: compare foundImgRepo and sbomImgRepo
			return imgTag == sbomTag
		})
	})

	return img, ok, nil
}

func (step *sbomStep) GetImageBOM(ctx context.Context, werfImgName, imageRef string, imageInfo *image.Info) (*cdx.BOM, error) {
	if sbom.IsScratchImage(imageRef) {
		return sbom.NewEmptyBOM(), nil
	}

	if imageInfo == nil {
		return nil, fmt.Errorf("image info not available for %q", imageRef)
	}

	return step.pullImageSbom(ctx, werfImgName, imageInfo)
}

func (step *sbomStep) pullImageSbom(ctx context.Context, werfImgName string, imageInfo *image.Info) (*cdx.BOM, error) {
	sbomImageName, err := step.resolveImageSbomName(imageInfo)
	if err != nil {
		return nil, err
	}

	if err = logboek.Context(ctx).Default().LogProcess("image %s: image SBOM processing (%s)", werfImgName, imageInfo.Name).DoError(func() error {
		return step.ensureSbomImageExists(ctx, sbomImageName, imageInfo.Name)
	}); err != nil {
		return nil, fmt.Errorf("unable to pull image SBOM: %w", err)
	}

	opener := func() (io.ReadCloser, error) {
		return step.containerBackend.SaveImageToStream(ctx, sbomImageName)
	}

	bom, err := sbom.ExtractBOMFromImage(opener)
	if err != nil {
		return nil, fmt.Errorf("unable to extract BOM from SBOM image %q: %w", sbomImageName, err)
	}

	return bom, nil
}

func (step *sbomStep) resolveImageSbomName(baseImageInfo *image.Info) (string, error) {
	if digest, ok := baseImageInfo.Labels[image.WerfStageContentDigestLabel]; ok && digest != "" {
		_, tag := image.ParseRepositoryAndTag(baseImageInfo.Name)

		return sbom.BaseImageSbomName(baseImageInfo.Repository, tag), nil
	}

	return "", fmt.Errorf(
		"unable to resolve SBOM name for image %q: required werf stage content digest label is missing",
		baseImageInfo.Name,
	)
}

func (step *sbomStep) ensureSbomImageExists(ctx context.Context, sbomImageName, sourceImageName string) error {
	if info, err := step.containerBackend.GetImageInfo(ctx, sbomImageName, container_backend.GetImageInfoOpts{}); err == nil && info != nil {
		logboek.Context(ctx).Default().LogF("Using local image SBOM %s\n", sbomImageName)

		return nil
	}

	if step.isLocalStorage {
		return fmt.Errorf("SBOM for image %q not found locally", sourceImageName)
	}

	logboek.Context(ctx).Default().LogF("Pulling image SBOM from %s\n", sbomImageName)
	if err := step.containerBackend.Pull(ctx, sbomImageName, container_backend.PullOpts{}); err != nil {
		return fmt.Errorf("SBOM for image %q not found in container registry: %w", sourceImageName, err)
	}

	return nil
}
