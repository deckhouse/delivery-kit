package stage

import (
	"context"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/build/signing"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/image"
)

type VexStagePublisher func(ctx context.Context, parentDesc *image.StageDesc, imageName, targetPlatform string, vexJSON []byte, signer signature.Signer, signerIdentity string) error

type VexStageOptions struct {
	VexJSON          []byte
	BaseStageOptions *BaseStageOptions
	SigningOptions   signing.VexSigningOptions
	Publisher        VexStagePublisher
}

type VexStage struct {
	*BaseStage

	vexJSON        []byte
	signer         signature.Signer
	signerIdentity string
	publisher      VexStagePublisher
}

func GenerateVexStage(vexJSON []byte, baseStageOptions *BaseStageOptions, vexSigningOptions signing.VexSigningOptions) *VexStage {
	return NewVexStage(VexStageOptions{
		VexJSON:          vexJSON,
		BaseStageOptions: baseStageOptions,
		SigningOptions:   vexSigningOptions,
	})
}

func NewVexStage(options VexStageOptions) *VexStage {
	return newVexStage(options.VexJSON, options.BaseStageOptions, options.SigningOptions, options.Publisher)
}

func newVexStage(vexJSON []byte, baseStageOptions *BaseStageOptions, vexSigningOptions signing.VexSigningOptions, publisher VexStagePublisher) *VexStage {
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
		publisher:      publisher,
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

	return CalculateVexStageChecksum(s.vexJSON, parentDigest, s.signerIdentity), nil
}

func (s *VexStage) GetContentDependencies(ctx context.Context, c Conveyor, buildContextArchive container_backend.BuildContextArchiver) (string, error) {
	return s.GetDependencies(ctx, c, nil, nil, nil, buildContextArchive)
}

func (s *VexStage) MutateImage(ctx context.Context, _ ImageMutatorPusher, prevBuiltImage, stageImage *StageImage) error {
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

	if s.publisher == nil {
		return fmt.Errorf("VEX stage publisher is unavailable")
	}

	return s.publisher(ctx, parentDesc, s.ImageName(), s.TargetPlatform(), s.vexJSON, s.signer, s.signerIdentity)
}

const vexStageArtifactFormatVersion = "2"

// CalculateVexStageChecksum returns the cache identity for a VEX artifact.
func CalculateVexStageChecksum(vexJSON []byte, parentDigest, signerIdentity string) string {
	parts := []string{
		vexStageArtifactFormatVersion,
		util.Sha256Hash(string(vexJSON)),
		parentDigest,
		signerIdentity,
	}
	return util.Sha256Hash(strings.Join(parts, "-"))
}
