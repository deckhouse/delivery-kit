package build

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

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
	"github.com/werf/werf/v2/pkg/sbom/externalref"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
	"github.com/werf/werf/v2/pkg/sbom/managedinput"
	osPm "github.com/werf/werf/v2/pkg/sbom/packages/os_pm"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/pkg/werf/global_warnings"
)

//go:generate mockgen -source sbom_processor.go -package mock -destination ../../test/mock/bom_patcher.go -mock_names BOMPatcherInterface=MockBOMPatcher

type BOMPatcherInterface interface {
	Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error)
}

// ErrSbomNotRequired indicates that SBOM is intentionally absent for the image
// (e.g. it is a trusted builder image). Callers should handle this silently.
var ErrSbomNotRequired = errors.New("sbom not required")

type sbomProcessor struct {
	containerBackend container_backend.ContainerBackend
	stagesStorage    storage.StagesStorage

	gostWarnOnce sync.Once
}

func newSbomProcessor(
	backend container_backend.ContainerBackend,
	stagesStorage storage.StagesStorage,
) *sbomProcessor {
	return &sbomProcessor{
		containerBackend: backend,
		stagesStorage:    stagesStorage,
	}
}

func (processor *sbomProcessor) ConvergeWithMerge(ctx context.Context, werfImgName string, stageDesc *image.StageDesc, scanOpts scanner.ScanOptions, mergeOpts cyclonedxutil.MergeOpts, patchers []BOMPatcherInterface, osPmEnabled, isStapelScratch bool, targetPlatform string, signer signature.Signer, signerIdentity string) error {
	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	scanOpts.Commands[0].SourcePath = stageDesc.Info.Name

	if err := processor.prepareGostComponents(ctx, &mergeOpts); err != nil {
		return err
	}

	checksum := processor.calculateStableChecksum(scanOpts, mergeOpts, signerIdentity, targetPlatform)

	store := artifact.NewOCIStore(repo, werfImgName)

	desc, found, err := attestation.FindAttachedArtifact(ctx, store, parentDigest, attestation.PredicateKindCycloneDX)
	if err != nil {
		return fmt.Errorf("check SBOM cache: %w", err)
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		logboek.Context(ctx).Default().LogF("image %s: Use previously generated SBOM from registry\n", werfImgName)
		return nil
	}

	if err := processor.containerBackend.Pull(ctx, stageDesc.Info.Name, container_backend.PullOpts{TargetPlatform: targetPlatform}); err != nil {
		return fmt.Errorf("unable to pull %q: %w", stageDesc.Info.Name, err)
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: SBOM processing", werfImgName).DoError(func() error {
		var targetBOM *cdx.BOM

		if (osPmEnabled || isStapelScratch) && len(scanOpts.Commands[0].Catalogers) == 0 {
			targetBOM = cyclonedxutil.NewBOM()
			targetBOM.Metadata = &cdx.Metadata{
				Component: &cdx.Component{
					Type:    cdx.ComponentTypeContainer,
					Name:    stageDesc.Info.Repository,
					Version: stageDesc.Info.Tag,
				},
			}
		} else {
			bomJSON, err := processor.containerBackend.GenerateSBOM(ctx, scanOpts)
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

		if osPmEnabled {
			pmBOM, err := osPm.CollectBOM(ctx, processor.containerBackend, stageDesc.Info.Name)
			if err != nil {
				return fmt.Errorf("collect os-pm BOM: %w", err)
			}
			if pmBOM != nil {
				resultBOM, err = cyclonedxutil.MergeBOMs(resultBOM, cyclonedxutil.MergeOpts{
					ImportBOMs: []*cdx.BOM{pmBOM},
				})
				if err != nil {
					return fmt.Errorf("merge os-pm BOM: %w", err)
				}
			}
		}

		for _, patcher := range patchers {
			if patcher == nil {
				continue
			}
			if _, isExternalRef := patcher.(*externalref.ExternalRefPatcher); isExternalRef {
				if err := logboek.Context(ctx).Default().LogProcess("Resolve external references").DoError(func() error {
					patchedBOM, applyErr := patcher.Apply(ctx, resultBOM)
					if applyErr != nil {
						if errors.Is(applyErr, externalref.ErrExternalRefEnrich) {
							logboek.Context(ctx).Warn().LogF("WARNING: %s\n", applyErr)
						}
						return applyErr
					}
					resultBOM = patchedBOM
					return nil
				}); err != nil {
					return err
				}
				continue
			}
			resultBOM, err = patcher.Apply(ctx, resultBOM)
			if err != nil {
				return err
			}
		}

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

// calculateStableChecksum computes the SBOM artifact cache checksum. Together with the
// parent stage digest it forms the cache key: a previously attached SBOM is reused only
// when both match, so the checksum must cover every generation input outside the image
// content. Intentionally excluded: image filesystem content, the scratch-base mode and
// the os-pm packages directive (all covered by the parent digest — the directive feeds
// the Packages stage digest through the generated install command), gomod patcher inputs
// (build context changes alter the stage digest), external reference enrichment
// (non-deterministic external data), and generator logic changes (covered by
// sbomArtifactFormatVersion).
func (processor *sbomProcessor) calculateStableChecksum(scanOpts scanner.ScanOptions, mergeOpts cyclonedxutil.MergeOpts, signerIdentity, targetPlatform string) string {
	return util.Sha256Hash(
		sbomArtifactFormatVersion,
		"scan", scanOpts.Checksum(),
		"merge", mergeOpts.Checksum(),
		"gost_attack_surface", mergeOpts.Gost.AttackSurface.String(),
		"gost_security_function", mergeOpts.Gost.SecurityFunction.String(),
		"signer", signerIdentity,
		"platform", targetPlatform,
	)
}

// PropagateArtifacts copies the artifacts attached to the image stage (e.g. its SBOM)
// into the final repo and the cache repos. Stages themselves are copied there before
// SBOM generation runs, so the artifacts have to catch up separately.
func (processor *sbomProcessor) PropagateArtifacts(ctx context.Context, projectName, werfImgName string, stageDesc, finalStageDesc *image.StageDesc, cacheStagesStorageList []storage.StagesStorage) error {
	return propagateArtifacts(ctx, projectName, werfImgName, stageDesc, finalStageDesc, cacheStagesStorageList)
}

func (processor *sbomProcessor) GetImageBOM(ctx context.Context, imageName string, imageInfo *image.Info) (*cdx.BOM, error) {
	if imageInfo == nil {
		return nil, fmt.Errorf("image info is nil for %q", imageName)
	}

	bom, err := processor.pullImageSbom(ctx, imageName, imageInfo)
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
				return nil, fmt.Errorf("the image %q must have an SBOM artifact attached; the image is a builder image but SBOM is required; %w", imageInfo.Name, err)
			}
		}
		return nil, sbomMissingError(imageInfo, err)
	}

	return bom, nil
}

func sbomMissingError(imageInfo *image.Info, err error) error {
	return fmt.Errorf("the image %q must have an SBOM artifact attached; to generate an SBOM for the image, rebuild it with SBOM generation enabled; note: if the image is a multi-platform image built by an older werf version, its SBOM is attached in a legacy platform-ambiguous format and cannot be used — rebuild the image with a newer werf version: %w", imageInfo.Name, err)
}

func (processor *sbomProcessor) pullImageSbom(ctx context.Context, imageName string, imageInfo *image.Info) (*cdx.BOM, error) {
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

func (processor *sbomProcessor) prepareGostComponents(ctx context.Context, mergeOpts *cyclonedxutil.MergeOpts) error {
	if !mergeOpts.Gost.AttackSurface.IsUndefined() || !mergeOpts.Gost.SecurityFunction.IsUndefined() {
		processor.gostWarnOnce.Do(func() {
			logboek.Context(ctx).Default().LogF("Warning: GOST SBOM integration is experimental and its behavior may change in the future\n")
		})
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
