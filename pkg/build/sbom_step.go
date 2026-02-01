package build

import (
	"context"
	"fmt"
	"io"
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

// Converge searches relevant SBOM image in local and remote storages.
// If the relevant image is found, it does nothing.
// Otherwise, it generates new sbom image and pushes that image into remote storage.
func (step *sbomStep) Converge(ctx context.Context, werfImgName string, stageDesc *image.StageDesc, scanOpts scanner.ScanOptions) error {
	sourceImageName := stageDesc.Info.Name
	sbomImageName := sbom.ImageName(sourceImageName)

	scanOpts.Commands[0].SourcePath = sourceImageName

	sbomBaseImgLabels := step.prepareSbomBaseLabels(ctx, stageDesc.Info.Labels, scanOpts)
	sbomImgLabels := step.prepareSbomLabels(ctx, stageDesc.Info.Labels, scanOpts)

	return logboek.Context(ctx).Default().LogProcess("image %s: SBOM processing", werfImgName).DoError(func() error {
		_, ok, err := step.findSbomImageLocally(ctx, sbomBaseImgLabels, sbomImageName)
		if err != nil {
			return err
		}
		logboek.Context(ctx).Debug().LogF("-- sbom_phase.Converge: sbom image is found locally=%t\n", ok)

		if step.isLocalStorage {
			if ok {
				logboek.Context(ctx).Default().LogLn("Use previously generated image from local backend storage")
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
					logboek.Context(ctx).Default().LogLn("Use previously generated image from container registry")
					return nil
				}
			}
		}

		// SBOM scanning is local operation. Ensure source image exist locally.
		if !step.isLocalStorage {
			if err := step.containerBackend.Pull(ctx, sourceImageName, container_backend.PullOpts{}); err != nil {
				return fmt.Errorf("unable to pull %q: %w", sourceImageName, err)
			}
		}

		tmpImgId, err := step.containerBackend.GenerateSBOM(ctx, scanOpts, sbomImgLabels.ToStringSlice())
		if err != nil {
			return fmt.Errorf("unable to scan source image and store the result: %w", err)
		}

		if err = step.containerBackend.Tag(ctx, tmpImgId, sbomImageName, container_backend.TagOpts{}); err != nil {
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

func (step *sbomStep) prepareSbomBaseLabels(_ context.Context, srcImgLabels map[string]string, scanOpts scanner.ScanOptions) label.LabelList {
	return label.LabelList{
		label.NewLabel(image.WerfLabel, srcImgLabels[image.WerfLabel]),
		label.NewLabel(image.WerfProjectRepoCommitLabel, srcImgLabels[image.WerfProjectRepoCommitLabel]),
		label.NewLabel(image.WerfStageContentDigestLabel, srcImgLabels[image.WerfStageContentDigestLabel]),
		label.NewLabel(image.WerfSbomLabel, scanOpts.Checksum()),
	}
}

func (step *sbomStep) prepareSbomLabels(ctx context.Context, srcImgLabels map[string]string, scanOpts scanner.ScanOptions) label.LabelList {
	list := step.prepareSbomBaseLabels(ctx, srcImgLabels, scanOpts)
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

func (step *sbomStep) PullImageSbom(ctx context.Context, werfImgName string, baseImageInfo *image.Info) (string, error) {
	sbomImageName, err := step.resolveImageSbomName(baseImageInfo)
	if err != nil {
		return "", err
	}

	err = logboek.Context(ctx).Default().LogProcess("image %s: image SBOM processing (%s)", werfImgName, baseImageInfo.Name).DoError(func() error {
		return step.ensureSbomImageExists(ctx, sbomImageName, baseImageInfo.Name)
	})
	if err != nil {
		return "", fmt.Errorf("unable to pull image SBOM: %w", err)
	}

	return sbomImageName, nil
}

func (step *sbomStep) resolveImageSbomName(baseImageInfo *image.Info) (string, error) {
	if digest, ok := baseImageInfo.Labels[image.WerfStageContentDigestLabel]; ok && digest != "" {
		_, tag := image.ParseRepositoryAndTag(baseImageInfo.Name)
		_, creationTs, err := image.GetDigestAndCreationTsFromLocalStageImageTag(tag)
		if err != nil {
			return "", fmt.Errorf("unable to parse image tag %q: %w", tag, err)
		}

		return sbom.BaseImageSbomName(baseImageInfo.Repository, digest, creationTs), nil
	}

	return "", fmt.Errorf(
		"unable to resolve SBOM name for image %q: no werf labels and no RepoDigest available",
		baseImageInfo.Name,
	)
}

func (step *sbomStep) ensureSbomImageExists(ctx context.Context, sbomImageName, sourceImageName string) error {
	if info, err := step.containerBackend.GetImageInfo(ctx, sbomImageName, container_backend.GetImageInfoOpts{}); err == nil && info != nil {
		logboek.Context(ctx).Default().LogF("Using local image SBOM %s\n", sbomImageName)

		return nil
	}

	if step.isLocalStorage {
		return fmt.Errorf("SBOM for image %q not found locally (expected %q)", sourceImageName, sbomImageName)
	}

	logboek.Context(ctx).Default().LogF("Pulling image SBOM from %s\n", sbomImageName)
	if err := step.containerBackend.Pull(ctx, sbomImageName, container_backend.PullOpts{}); err != nil {
		return fmt.Errorf("SBOM for image %q not found in container registry (expected %q): %w", sourceImageName, sbomImageName, err)
	}

	return nil
}

// CopyFromSBOMCollector is an alias for sbom.SBOMCollector for backward compatibility.
type CopyFromSBOMCollector = sbom.SBOMCollector

// NewCopyFromSBOMCollector creates a new CopyFromSBOMCollector.
func NewCopyFromSBOMCollector() *CopyFromSBOMCollector {
	return sbom.NewSBOMCollector()
}

// PullAndFilterCopyFromSbom pulls SBOM for the COPY --from source image and filters it.
// Returns the filtered SBOM containing only components that match the copied paths.
func (step *sbomStep) PullAndFilterCopyFromSbom(ctx context.Context, werfImgName string, entry sbom.CopyFromEntry) (*cdx.BOM, error) {
	if step.isLocalStorage {
		return nil, nil
	}

	sbomImageName := sbom.ImageName(entry.SourceImageRef)

	var filteredBOM *cdx.BOM

	if err := logboek.Context(ctx).Default().LogProcess("image %s: COPY --from SBOM processing (%s)", werfImgName, entry.SourceImageRef).DoError(func() error {
		logboek.Context(ctx).Default().LogF("Pulling SBOM from %s\n", sbomImageName)

		// Pull the SBOM image
		if err := step.containerBackend.Pull(ctx, sbomImageName, container_backend.PullOpts{}); err != nil {
			return fmt.Errorf("SBOM for image %q not found in container registry (expected %q): %w", entry.SourceImageRef, sbomImageName, err)
		}

		// Create opener for the SBOM image
		opener := func() (io.ReadCloser, error) {
			return step.containerBackend.SaveImageToStream(ctx, sbomImageName)
		}

		// Extract and filter SBOM
		_, filtered, err := sbom.ExtractAndFilterSBOM(ctx, opener, entry.SourcePaths, entry.DestPath)
		if err != nil {
			return fmt.Errorf("unable to extract and filter SBOM: %w", err)
		}

		filteredBOM = filtered

		logboek.Context(ctx).Default().LogF("Filtered %d components for paths %v -> %s\n",
			sbom.GetComponentsCount(filteredBOM), entry.SourcePaths, entry.DestPath)

		return nil
	}); err != nil {
		return nil, fmt.Errorf("unable to process COPY --from SBOM: %w", err)
	}

	return filteredBOM, nil
}
