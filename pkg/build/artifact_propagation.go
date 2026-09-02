package build

import (
	"context"
	"fmt"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/pkg/storage/manager"
)

func ensureAttachedArtifacts(ctx context.Context, repository, digest string) error {
	if repository == "" || repository == storage.LocalStorageAddress || digest == "" {
		return fmt.Errorf("artifact source descriptor is incomplete")
	}

	index, err := artifact.PullFallbackIndex(ctx, repository, digest)
	if err != nil {
		return fmt.Errorf("check source artifact index %s@%s: %w", repository, digest, err)
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return fmt.Errorf("read source artifact index %s@%s: %w", repository, digest, err)
	}
	if len(manifest.Manifests) == 0 {
		return fmt.Errorf("source image %s@%s has no attached artifacts", repository, digest)
	}

	return nil
}

func propagateArtifacts(ctx context.Context, projectName, imageName string, source, destination *image.StageDesc, caches []storage.StagesStorage, sourceStorages ...storage.StagesStorage) error {
	var sourceStorage storage.StagesStorage
	if len(sourceStorages) > 0 {
		sourceStorage = sourceStorages[0]
	}
	return propagateArtifactsWithManager(ctx, projectName, imageName, source, destination, caches, sourceStorage, nil, nil)
}

func propagateArtifactsWithManager(ctx context.Context, projectName, imageName string, source, destination *image.StageDesc, caches []storage.StagesStorage, sourceStorage, destinationStorage storage.StagesStorage, storageManager manager.StorageManagerInterface) error {
	if source == nil || source.Info == nil {
		return fmt.Errorf("source image descriptor is unavailable")
	}
	if source.Info.Repository == "" || source.Info.Repository == storage.LocalStorageAddress {
		return nil
	}

	if sourceStorage == nil {
		sourceStorage = &storage.RepoStagesStorage{RepoAddress: source.Info.Repository}
	}

	copyArtifacts := func(ctx context.Context, sourceStorage storage.StagesStorage, sourceDigest string, destinationStorage storage.StagesStorage, destinationDigest string) error {
		if storageManager != nil {
			return storageManager.CopyAttachedArtifacts(ctx, sourceStorage, sourceDigest, destinationStorage, destinationDigest)
		}
		return sourceStorage.CopyAttachedArtifacts(ctx, sourceStorage.Address(), sourceDigest, destinationStorage.Address(), destinationDigest)
	}

	if destination != nil && destination.Info != nil &&
		destination.Info.Repository != "" &&
		destination.Info.Repository != storage.LocalStorageAddress &&
		destination.Info.Repository != source.Info.Repository {
		if destinationStorage == nil || destinationStorage.Address() != destination.Info.Repository {
			destinationStorage = &storage.RepoStagesStorage{RepoAddress: destination.Info.Repository}
		}
		if err := logboek.Context(ctx).Default().LogProcess("image %s: copy artifacts into final repo %s", imageName, destination.Info.Repository).DoError(func() error {
			return copyArtifacts(ctx, sourceStorage, source.Info.GetDigest(), destinationStorage, destination.Info.GetDigest())
		}); err != nil {
			return fmt.Errorf("copy attached artifacts into final repo %s: %w", destination.Info.Repository, err)
		}
	}

	for _, cache := range caches {
		if cache == nil || cache.Address() == storage.LocalStorageAddress || cache.Address() == source.Info.Repository {
			continue
		}

		destinationDigest := source.Info.GetDigest()
		if projectName != "" && source.StageID != nil && source.StageID.Digest != "" {
			cacheDesc, err := cache.GetStageDesc(ctx, projectName, *source.StageID)
			if err != nil || cacheDesc == nil || cacheDesc.Info == nil {
				if err == nil {
					err = fmt.Errorf("cache stage descriptor is unavailable")
				}
				logboek.Context(ctx).Warn().LogF("Warning: unable to resolve destination descriptor in cache stages storage %s: %s\n", cache.String(), err)
				continue
			}
			destinationDigest = cacheDesc.Info.GetDigest()
		}

		if err := copyArtifacts(ctx, sourceStorage, source.Info.GetDigest(), cache, destinationDigest); err != nil {
			logboek.Context(ctx).Warn().LogF("Warning: unable to copy artifacts into cache stages storage %s: %s\n", cache.String(), err)
		}
	}

	return nil
}
