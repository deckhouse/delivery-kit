package stage

import (
	"context"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/build/signing"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	vexImage "github.com/werf/werf/v2/pkg/vex/image"
)

type VexStage struct {
	*BaseStage

	vexJSON        []byte
	signer         signature.Signer
	signerIdentity string
}

func GenerateVexStage(vexJSON []byte, baseStageOptions *BaseStageOptions, vexSigningOptions signing.VexSigningOptions) *VexStage {
	return newVexStage(vexJSON, baseStageOptions, vexSigningOptions)
}

func newVexStage(vexJSON []byte, baseStageOptions *BaseStageOptions, vexSigningOptions signing.VexSigningOptions) *VexStage {
	var signer signature.Signer
	var signerIdentity string
	if vexSigningOptions.Enabled {
		signer = vexSigningOptions.Signer().SignerVerifier()
		signerIdentity = vexSigningOptions.Signer().Fingerprint()
	}

	stage := &VexStage{
		BaseStage:      NewBaseStage(Vex, baseStageOptions),
		vexJSON:        vexJSON,
		signer:         signer,
		signerIdentity: signerIdentity,
	}
	stage.SetArtifactMetadata(&ArtifactStageMetadata{
		Kind:           ArtifactKindVex,
		TargetPlatform: baseStageOptions.TargetPlatform,
		Mutable:        true,
		Buildable:      false,
	})
	return stage
}

var _ Interface = (*VexStage)(nil)

func (s *VexStage) IsBuildable() bool {
	return false
}

func (s *VexStage) IsMutable() bool {
	return true
}

func (s *VexStage) PrepareImage(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, _ *StageImage, _ container_backend.BuildContextArchiver) error {
	return nil
}

func (s *VexStage) GetDependencies(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, prevBuiltImage *StageImage, _ container_backend.BuildContextArchiver) (string, error) {
	parentDigest := ""
	if prevBuiltImage != nil && prevBuiltImage.Image != nil {
		if stageDesc := prevBuiltImage.Image.GetStageDesc(); stageDesc != nil && stageDesc.Info != nil {
			parentDigest = stageDesc.Info.GetDigest()
		}
	}

	return calculateVexStageChecksum(s.vexJSON, parentDigest, s.signerIdentity), nil
}

func (s *VexStage) GetContentDependencies(ctx context.Context, c Conveyor, buildContextArchive container_backend.BuildContextArchiver) (string, error) {
	return s.GetDependencies(ctx, c, nil, nil, nil, buildContextArchive)
}

func (s *VexStage) MutateImage(ctx context.Context, stagesStorage ImageMutatorPusher, prevBuiltImage, stageImage *StageImage) error {
	if _, err := registryFromImageMutatorPusher(stagesStorage); err != nil {
		return err
	}
	if prevBuiltImage == nil || prevBuiltImage.Image == nil {
		return fmt.Errorf("VEX stage parent image is unavailable")
	}
	if stageImage == nil || stageImage.Image == nil {
		return fmt.Errorf("VEX stage image is unavailable")
	}

	parentDesc := prevBuiltImage.Image.GetStageDesc()
	if parentDesc == nil || parentDesc.Info == nil {
		return fmt.Errorf("VEX stage parent descriptor is unavailable")
	}
	if parentDesc.Info.Repository == "" {
		return fmt.Errorf("VEX stage parent descriptor repository is empty")
	}

	parentDigest := parentDesc.Info.GetDigest()
	if parentDigest == "" {
		return fmt.Errorf("VEX stage parent descriptor digest is empty")
	}

	metadata := s.GetArtifactMetadata()
	metadata.ParentDigest = parentDigest

	checksum := calculateVexStageChecksum(s.vexJSON, parentDigest, s.signerIdentity)
	store := artifact.NewOCIStore(parentDesc.Info.Repository, stageImage.Image.Name())
	needed, err := checkVexStagePublishNeeded(ctx, store, parentDigest, checksum)
	if err != nil {
		return fmt.Errorf("check VEX publish needed: %w", err)
	}
	if !needed {
		logboek.Context(ctx).Default().LogF("image %s: VEX artifact is up to date — skipping publish\n", stageImage.Image.Name())
		return nil
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: Published VEX artifact", stageImage.Image.Name()).DoError(func() error {
		return vexImage.PushVEX(ctx, s.vexJSON, parentDesc.Info.Repository, parentDigest, s.ImageName(), checksum, s.TargetPlatform(), s.signer)
	})
}

const vexStageArtifactFormatVersion = "2"

func calculateVexStageChecksum(vexJSON []byte, parentDigest, signerIdentity string) string {
	parts := []string{
		vexStageArtifactFormatVersion,
		util.Sha256Hash(string(vexJSON)),
		parentDigest,
		signerIdentity,
	}
	return util.Sha256Hash(strings.Join(parts, "-"))
}

func checkVexStagePublishNeeded(ctx context.Context, store artifact.Store, parentDigest, checksum string) (bool, error) {
	desc, found, err := attestation.FindAttachedArtifact(ctx, store, parentDigest, attestation.PredicateKindOpenVEX)
	if err != nil {
		return false, fmt.Errorf("check VEX cache: %w", err)
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		return false, nil
	}
	return true, nil
}
