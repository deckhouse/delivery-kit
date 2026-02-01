package stage

import (
	"context"

	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/image"
)

// CopyFromInfo contains information about COPY --from instruction.
type CopyFromInfo struct {
	// SourceImageRef is the reference to the source image (external image name or resolved stage reference).
	SourceImageRef string
	// SourcePaths are the source paths from the COPY instruction.
	SourcePaths []string
	// DestPath is the destination path in the target image.
	DestPath string
	// IsExternalImage indicates if the source is an external image (not a stage in current build).
	IsExternalImage bool
}

// CopyFromInfoProvider is an interface for stages that provide COPY --from information.
type CopyFromInfoProvider interface {
	GetCopyFromInfo() *CopyFromInfo
}

type Interface interface {
	Name() StageName
	LogDetailedName() string

	IsEmpty(ctx context.Context, c Conveyor, prevBuiltImage *StageImage) (bool, error)
	IsBuildable() bool
	IsMutable() bool

	ExpandDependencies(ctx context.Context, c Conveyor, baseEnv map[string]string) error
	FetchDependencies(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, dockerRegistry docker_registry.GenericApiInterface) error
	GetDependencies(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevImage, prevBuiltImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) (string, error)
	GetNextStageDependencies(ctx context.Context, c Conveyor) (string, error)

	PrepareImage(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevBuiltImage, stageImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) error

	PreRun(context.Context, Conveyor) error

	SetDigest(digest string)
	GetDigest() string

	SetContentDigest(contentDigest string)
	GetContentDigest() string

	SetStageImage(*StageImage)
	GetStageImage() *StageImage

	SetGitMappings([]*GitMapping)
	GetGitMappings() []*GitMapping

	MutateImage(ctx context.Context, registry ImageMutatorPusher, prevBuiltImage, stageImage *StageImage) error

	SelectSuitableStageDesc(context.Context, Conveyor, image.StageDescSet) (*image.StageDesc, error)

	HasPrevStage() bool
	IsStapelStage() bool

	UsesBuildContext() bool

	SetMeta(meta *StageMeta)
	GetMeta() *StageMeta
}
