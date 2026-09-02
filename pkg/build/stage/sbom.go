package stage

import (
	"context"
	"fmt"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/build/signing"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/image"
)

type SbomStagePublisher func(ctx context.Context, parentDesc *image.StageDesc, imageName, targetPlatform string) error

type SbomStageOptions struct {
	BaseStageOptions *BaseStageOptions
	SigningOptions   signing.SbomSigningOptions
	Dependency       string
	Publisher        SbomStagePublisher
}

type SbomStage struct {
	*BaseStage

	publisher      SbomStagePublisher
	dependency     string
	signerIdentity string
}

func GenerateSbomStage(baseStageOptions *BaseStageOptions, sbomSigningOptions signing.SbomSigningOptions, dependency string, publisher SbomStagePublisher) *SbomStage {
	return NewSbomStage(SbomStageOptions{
		BaseStageOptions: baseStageOptions,
		SigningOptions:   sbomSigningOptions,
		Dependency:       dependency,
		Publisher:        publisher,
	})
}

func NewSbomStage(options SbomStageOptions) *SbomStage {
	return newSbomStage(options.BaseStageOptions, options.SigningOptions, options.Dependency, options.Publisher)
}

func newSbomStage(baseStageOptions *BaseStageOptions, sbomSigningOptions signing.SbomSigningOptions, dependency string, publisher SbomStagePublisher) *SbomStage {
	var signerIdentity string
	if sbomSigningOptions.Enabled {
		signerIdentity = sbomSigningOptions.Signer().Fingerprint()
	}

	stage := &SbomStage{
		BaseStage:      NewBaseStage(Sbom, baseStageOptions),
		publisher:      publisher,
		dependency:     dependency,
		signerIdentity: signerIdentity,
	}
	stage.SetArtifactMetadata(&ArtifactStageMetadata{
		Kind:           ArtifactKindSbom,
		TargetPlatform: baseStageOptions.TargetPlatform,
		Mutable:        true,
		Buildable:      false,
	})
	return stage
}

var _ Interface = (*SbomStage)(nil)

func (s *SbomStage) IsBuildable() bool {
	return false
}

func (s *SbomStage) IsMutable() bool {
	return true
}

func (s *SbomStage) PrepareImage(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, _ *StageImage, _ container_backend.BuildContextArchiver) error {
	return nil
}

func (s *SbomStage) GetDependencies(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, prevBuiltImage *StageImage, _ container_backend.BuildContextArchiver) (string, error) {
	parentDigest := ""
	if prevBuiltImage != nil && prevBuiltImage.Image != nil {
		if stageDesc := prevBuiltImage.Image.GetStageDesc(); stageDesc != nil && stageDesc.Info != nil {
			parentDigest = stageDesc.Info.GetDigest()
		}
	}

	return util.Sha256Hash(
		sbomArtifactFormatVersion,
		"inputs", s.dependency,
		"parent", parentDigest,
		"signer", s.signerIdentity,
		"platform", s.TargetPlatform(),
	), nil
}

func (s *SbomStage) GetContentDependencies(ctx context.Context, c Conveyor, buildContextArchive container_backend.BuildContextArchiver) (string, error) {
	return s.GetDependencies(ctx, c, nil, nil, nil, buildContextArchive)
}

func (s *SbomStage) MutateArtifact(ctx context.Context, prevBuiltImage, stageImage *StageImage) error {
	if s.publisher == nil {
		return fmt.Errorf("SBOM stage publisher is unavailable")
	}
	if prevBuiltImage == nil || prevBuiltImage.Image == nil {
		return fmt.Errorf("SBOM stage parent image is unavailable")
	}
	if stageImage == nil || stageImage.Image == nil {
		return fmt.Errorf("SBOM stage image is unavailable")
	}

	parentDesc := prevBuiltImage.Image.GetStageDesc()
	if parentDesc == nil || parentDesc.Info == nil {
		return fmt.Errorf("SBOM stage parent descriptor is unavailable")
	}
	if parentDesc.Info.Repository == "" {
		return fmt.Errorf("SBOM stage parent descriptor repository is empty")
	}
	if parentDesc.Info.GetDigest() == "" {
		return fmt.Errorf("SBOM stage parent descriptor digest is empty")
	}

	metadata := s.GetArtifactMetadata()
	metadata.ParentDigest = parentDesc.Info.GetDigest()

	return s.publisher(ctx, parentDesc, s.ImageName(), s.TargetPlatform())
}

func (s *SbomStage) MutateImage(_ context.Context, _ ImageMutatorPusher, _, _ *StageImage) error {
	return fmt.Errorf("SBOM stage must be mutated as an artifact")
}

const sbomArtifactFormatVersion = "2"
