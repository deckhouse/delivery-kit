package build

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/build/stage"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/pkg/storage/manager"
)

type vexProcessor struct {
	stagesStorage  storage.StagesStorage
	storageManager manager.StorageManagerInterface
}

func newVexProcessor(stagesStorage storage.StagesStorage, storageManager manager.StorageManagerInterface) *vexProcessor {
	return &vexProcessor{stagesStorage: stagesStorage, storageManager: storageManager}
}

func (processor *vexProcessor) Converge(ctx context.Context, vexJSON []byte, stageDesc *image.StageDesc, werfImgName, targetPlatform string, signer signature.Signer, signerIdentity string) error {
	parentDigest := stageDesc.Info.GetDigest()

	checksum := stage.CalculateVexStageChecksum(vexJSON, parentDigest, signerIdentity)

	desc, found, err := processor.storageManager.FindAttachedArtifact(ctx, processor.stagesStorage, parentDigest, werfImgName, attestation.PredicateKindOpenVEX)
	if err != nil {
		return fmt.Errorf("check VEX publish needed: %w", err)
	}
	needed := !found || desc.Annotations[image.WerfChecksumAnnotation] != checksum
	if !needed {
		logboek.Context(ctx).Default().LogF("image %s: VEX artifact is up to date — skipping publish\n", werfImgName)
		return nil
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: Published VEX artifact", werfImgName).DoError(func() error {
		return processor.storageManager.PublishAttestation(ctx, processor.stagesStorage, attestation.PredicateKindOpenVEX, vexJSON, parentDigest, werfImgName, attestation.PublishAttestationOptions{
			Signer: signer, Checksum: checksum, TargetPlatform: targetPlatform,
		})
	})
}
