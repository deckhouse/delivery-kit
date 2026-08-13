package build

import (
	"context"
	"fmt"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
	vexImage "github.com/werf/werf/v2/pkg/vex/image"
)

type vexStep struct{}

func newVexStep() *vexStep {
	return &vexStep{}
}

func (step *vexStep) Converge(ctx context.Context, vexJSON []byte, stageDesc *image.StageDesc, werfImgName, targetPlatform string) error {
	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	// Calculate checksum bound to both VEX content and image digest (FR-011).
	checksum := util.Sha256Hash(string(vexJSON) + "-" + parentDigest)

	store := artifact.NewOCIStore(repo, werfImgName)

	needed, err := checkVEXPublishNeeded(ctx, store, parentDigest, checksum)
	if err != nil {
		return fmt.Errorf("check VEX publish needed: %w", err)
	}
	if !needed {
		logboek.Context(ctx).Default().LogF("image %s: VEX artifact is up to date — skipping publish\n", werfImgName)
		return nil
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: Published VEX artifact", werfImgName).DoError(func() error {
		return vexImage.PushVEX(ctx, vexJSON, repo, parentDigest, werfImgName, checksum, targetPlatform)
	})
}

// checkVEXPublishNeeded returns true if the VEX artifact should be published
// (no existing OCI artifact or its checksum annotation differs from the current
// VEX file checksum), and false if publishing can be skipped (artifact exists
// with matching checksum).
func checkVEXPublishNeeded(ctx context.Context, store artifact.Store, parentDigest, checksum string) (bool, error) {
	desc, found, err := store.GetAttached(ctx, parentDigest, vex.DSSEMediaType)
	if err != nil {
		return false, fmt.Errorf("check VEX cache: %w", err)
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		return false, nil // skip publish
	}
	return true, nil // publish needed
}
