package build

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
	"github.com/werf/werf/v2/pkg/sbom/managedinput"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/pkg/werf/global_warnings"
)

//go:generate mockgen -source sbom_step.go -package mock -destination ../../test/mock/bom_patcher.go -mock_names BOMPatcherInterface=MockBOMPatcher

type BOMPatcherInterface interface {
	Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error)
}

// ErrSbomNotRequired indicates that SBOM is intentionally absent for the image
// (e.g. it is a trusted builder image). Callers should handle this silently.
var ErrSbomNotRequired = errors.New("sbom not required")

type sbomStep struct {
	containerBackend container_backend.ContainerBackend
	stagesStorage    storage.StagesStorage
}

func newSbomStep(
	backend container_backend.ContainerBackend,
	stagesStorage storage.StagesStorage,
) *sbomStep {
	return &sbomStep{
		containerBackend: backend,
		stagesStorage:    stagesStorage,
	}
}

func (step *sbomStep) ConvergeWithMerge(ctx context.Context, werfImgName string, stageDesc *image.StageDesc, scanOpts scanner.ScanOptions, mergeOpts cyclonedxutil.MergeOpts, patchers []BOMPatcherInterface, osPmLockPath string, isStapelScratch bool, targetPlatform string, signer signature.Signer, signerIdentity string) error {
	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	scanOpts.Commands[0].SourcePath = stageDesc.Info.Name

	if err := step.prepareGostComponents(ctx, &mergeOpts); err != nil {
		return err
	}

	checksum := step.calculateStableChecksum(scanOpts, mergeOpts, signerIdentity)

	store := artifact.NewOCIStore(repo, werfImgName)

	desc, found, err := store.GetAttached(ctx, parentDigest, attestation.BundleMediaType)
	if err != nil {
		return fmt.Errorf("check SBOM cache (bundle): %w", err)
	}
	if !found {
		desc, found, err = store.GetAttached(ctx, parentDigest, attestation.DSSEMediaType)
		if err != nil {
			return fmt.Errorf("check SBOM cache (dsse): %w", err)
		}
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		logboek.Context(ctx).Default().LogF("image %s: Use previously generated SBOM from registry\n", werfImgName)
		return nil
	}

	if err := step.containerBackend.Pull(ctx, stageDesc.Info.Name, container_backend.PullOpts{}); err != nil {
		return fmt.Errorf("unable to pull %q: %w", stageDesc.Info.Name, err)
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: SBOM processing", werfImgName).DoError(func() error {
		var targetBOM *cdx.BOM

		if (osPmLockPath != "" || isStapelScratch) && len(scanOpts.Commands[0].Catalogers) == 0 {
			targetBOM = cyclonedxutil.NewBOM()
			targetBOM.Metadata = &cdx.Metadata{
				Component: &cdx.Component{
					Type:    cdx.ComponentTypeContainer,
					Name:    stageDesc.Info.Repository,
					Version: stageDesc.Info.Tag,
				},
			}
		} else {
			bomJSON, err := step.containerBackend.GenerateSBOM(ctx, scanOpts)
			if err != nil {
				return fmt.Errorf("generate SBOM: %w", err)
			}

			targetBOM, err = cyclonedxutil.BuildCycloneDX16BOMFromJSON(bomJSON)
			if err != nil {
				return fmt.Errorf("parse scanned BOM: %w", err)
			}

			managedinput.FilterBOMBySourcePaths(targetBOM, scanOpts.Commands[0].Catalogers)
		}

		resultBOM := targetBOM
		if !mergeOpts.IsEmpty() {
			var err error
			resultBOM, err = cyclonedxutil.MergeBOMs(targetBOM, mergeOpts)
			if err != nil {
				return fmt.Errorf("merge BOMs: %w", err)
			}
		}

		for _, patcher := range patchers {
			if patcher == nil {
				continue
			}
			resultBOM, err = patcher.Apply(ctx, resultBOM)
			if err != nil {
				return err
			}
		}

		// GOST Upsert must run AFTER patchers so that components added by patchers
		// (e.g. PM BOMPatcher) also get GOST properties.
		if err := gost.Upsert(resultBOM, mergeOpts.Gost); err != nil {
			return fmt.Errorf("set GOST properties: %w", err)
		}

		resultJSON, err := cyclonedxutil.ToJSON(resultBOM)
		if err != nil {
			return fmt.Errorf("serialize BOM: %w", err)
		}

		if err := logboek.Context(ctx).Default().LogProcess("Push SBOM artifact").DoError(func() error {
			return sbomImage.PushSBOM(ctx, resultJSON, repo, parentDigest, werfImgName, checksum, targetPlatform, signer)
		}); err != nil {
			return err
		}

		return nil
	})
}

const sbomArtifactFormatVersion = "2"

func (step *sbomStep) calculateStableChecksum(scanOpts scanner.ScanOptions, mergeOpts cyclonedxutil.MergeOpts, signerIdentity string) string {
	var parts []string
	parts = append(parts, sbomArtifactFormatVersion)
	parts = append(parts, scanOpts.Checksum())
	parts = append(parts, mergeOpts.Checksum())
	parts = append(parts, signerIdentity)
	return util.Sha256Hash(strings.Join(parts, "-"))
}

// PropagateArtifacts copies the artifacts attached to the image stage (e.g. its SBOM)
// into the final repo and the cache repos. Stages themselves are copied there before
// SBOM generation runs, so the artifacts have to catch up separately.
func (step *sbomStep) PropagateArtifacts(ctx context.Context, werfImgName string, stageDesc, finalStageDesc *image.StageDesc, cacheStagesStorageList []storage.StagesStorage) error {
	srcRepo := stageDesc.Info.Repository
	srcDigest := stageDesc.Info.GetDigest()

	if finalStageDesc != nil && finalStageDesc.Info.Repository != srcRepo {
		if err := logboek.Context(ctx).Default().LogProcess("image %s: Copy SBOM artifacts into the final repo", werfImgName).DoError(func() error {
			return artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, finalStageDesc.Info.Repository, finalStageDesc.Info.GetDigest())
		}); err != nil {
			return fmt.Errorf("copy attached artifacts into final repo %s: %w", finalStageDesc.Info.Repository, err)
		}
	}

	for _, cache := range cacheStagesStorageList {
		if cache.Address() == storage.LocalStorageAddress || cache.Address() == srcRepo {
			continue
		}
		if err := logboek.Context(ctx).Info().LogProcess("image %s: Copy SBOM artifacts into cache %s", werfImgName, cache.String()).DoError(func() error {
			return artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, cache.Address(), srcDigest)
		}); err != nil {
			logboek.Context(ctx).Warn().LogF("Warning: unable to copy attached artifacts into cache stages storage %s: %s\n", cache.String(), err)
		}
	}

	return nil
}

func (step *sbomStep) GetImageBOM(ctx context.Context, imageName string, imageInfo *image.Info) (*cdx.BOM, error) {
	if imageInfo == nil {
		return nil, fmt.Errorf("image info is nil for %q", imageName)
	}

	bom, err := step.pullImageSbom(ctx, imageName, imageInfo)
	if err != nil {
		if isTrustedBuilderImage(imageInfo.Labels) {
			switch {
			case isGolangBuilderImage(imageInfo.Name), isAlpineBuilderImage(imageInfo.Name):
				global_warnings.GlobalWarningLn(ctx,
					fmt.Sprintf("The builder image %q is DEPRECATED and it WILL CAUSE AN ERROR in the future. Plan your migration to an up-to-date builder image.", imageInfo.Name))
				return nil, ErrSbomNotRequired
			default:
				if os.Getenv("WERF_E2E_ALLOW_LOCAL_BUILDER_IMAGES") == "true" {
					return nil, ErrSbomNotRequired
				}
				return nil, fmt.Errorf("the base image %q must have an SBOM artifact attached; the image is a builder image but SBOM is required; %w", imageInfo.Name, err)
			}
		}
		return nil, fmt.Errorf("the base image %q must have an SBOM artifact attached; to generate an SBOM for the base image, rebuild it with SBOM generation enabled: %w", imageInfo.Name, err)
	}

	return bom, nil
}

func (step *sbomStep) pullImageSbom(ctx context.Context, imageName string, imageInfo *image.Info) (*cdx.BOM, error) {
	parentDigest := imageInfo.GetDigest()
	if parentDigest == "" {
		return nil, fmt.Errorf("image digest not available for %q", imageInfo.Name)
	}

	bomJSON, err := sbomImage.PullSBOM(ctx, imageInfo.Repository, parentDigest, imageName)
	if err != nil {
		return nil, fmt.Errorf("pull SBOM for %q: %w", imageName, err)
	}

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(bomJSON)
	if err != nil {
		return nil, fmt.Errorf("parse CycloneDX BOM: %w", err)
	}

	return bom, nil
}

func (step *sbomStep) prepareGostComponents(ctx context.Context, mergeOpts *cyclonedxutil.MergeOpts) error {
	if !mergeOpts.Gost.AttackSurface.IsUndefined() || !mergeOpts.Gost.SecurityFunction.IsUndefined() {
		logboek.Context(ctx).Default().LogF("Warning: GOST SBOM integration is experimental and its behavior may change in the future\n")
	}

	// Skip GOST validation and upsert for base/import BOMs when GOST is not configured.
	// Without this guard, components from patchers (e.g. PM BOMPatcher) that lack GOST
	// properties would fail validation even though GOST is not in use.
	if mergeOpts.Gost.AttackSurface.IsUndefined() && mergeOpts.Gost.SecurityFunction.IsUndefined() {
		return nil
	}

	if mergeOpts.BaseBOM != nil {
		if err := gost.Validate(mergeOpts.BaseBOM); err != nil {
			return fmt.Errorf("base SBOM validation failed: %w", err)
		}
		if err := gost.Upsert(mergeOpts.BaseBOM, mergeOpts.Gost); err != nil {
			return fmt.Errorf("set GOST properties for base SBOM: %w", err)
		}
	}

	for i, externalBOM := range mergeOpts.ImportBOMs {
		if err := gost.Validate(externalBOM); err != nil {
			return fmt.Errorf("external SBOM [%d] validation failed: %w", i, err)
		}
		if err := gost.Upsert(externalBOM, mergeOpts.Gost); err != nil {
			return fmt.Errorf("set GOST properties for external SBOM [%d]: %w", i, err)
		}
	}

	return nil
}
