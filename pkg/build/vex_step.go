package build

import (
	"context"
	"fmt"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/storage"
	vexImage "github.com/werf/werf/v2/pkg/vex/image"
)

type vexStep struct {
	stagesStorage storage.StagesStorage
}

func newVexStep(stagesStorage storage.StagesStorage) *vexStep {
	return &vexStep{
		stagesStorage: stagesStorage,
	}
}

func (step *vexStep) Converge(ctx context.Context, vexJSON []byte, stageDesc *image.StageDesc, werfImgName, targetPlatform string) error {
	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	// Calculate checksum bound to both VEX content and image digest (FR-011).
	checksum := util.Sha256Hash(string(vexJSON) + "-" + parentDigest)

	store := artifact.NewOCIStore(repo, werfImgName)
	desc, found, err := store.GetAttached(ctx, parentDigest, vexImage.DSSEMediaType)
	if err != nil {
		return fmt.Errorf("check VEX cache: %w", err)
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		logboek.Context(ctx).Default().LogF("image %s: VEX artifact is up to date — skipping publish\n", werfImgName)
		return nil
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: Published VEX artifact", werfImgName).DoError(func() error {
		return vexImage.PushVEX(ctx, vexJSON, repo, parentDigest, werfImgName, checksum, targetPlatform)
	})
}
