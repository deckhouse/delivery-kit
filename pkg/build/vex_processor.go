package build

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/build/stage"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	vexImage "github.com/werf/werf/v2/pkg/vex/image"
)

type vexProcessor struct{}

func newVexProcessor() *vexProcessor {
	return &vexProcessor{}
}

func (processor *vexProcessor) Converge(ctx context.Context, vexJSON []byte, stageDesc *image.StageDesc, werfImgName, targetPlatform string, signer signature.Signer, signerIdentity string) error {
	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	checksum := stage.CalculateVexStageChecksum(vexJSON, parentDigest, signerIdentity)

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
		return vexImage.PushVEX(ctx, vexJSON, repo, parentDigest, werfImgName, checksum, targetPlatform, signer)
	})
}

// checkVEXPublishNeeded returns true if the VEX artifact should be published
// (no existing VEX artifact of either format or its checksum annotation differs
// from the current checksum), and false if publishing can be skipped. A legacy
// annotation-less entry never matches the current checksum formula, so it always
// triggers a republish regardless of its actual kind.
func checkVEXPublishNeeded(ctx context.Context, store artifact.Store, parentDigest, checksum string) (bool, error) {
	desc, found, err := attestation.FindAttachedArtifact(ctx, store, parentDigest, attestation.PredicateKindOpenVEX)
	if err != nil {
		return false, fmt.Errorf("check VEX cache: %w", err)
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		return false, nil
	}
	return true, nil
}
