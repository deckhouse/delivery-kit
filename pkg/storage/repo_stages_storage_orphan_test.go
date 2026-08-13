package storage

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/image"
)

type orphanedArtifactsRegistryStub struct {
	docker_registry.Interface

	tags            []string
	existingDigests map[string]bool
}

func (r *orphanedArtifactsRegistryStub) Tags(_ context.Context, _ string, _ ...docker_registry.Option) ([]string, error) {
	return r.tags, nil
}

func (r *orphanedArtifactsRegistryStub) TryGetRepoImage(_ context.Context, reference string) (*image.Info, error) {
	if r.existingDigests[reference] {
		return &image.Info{}, nil
	}
	return nil, nil
}

var _ = Describe("RepoStagesStorage.GetOrphanedArtifactNames", func() {
	const repoAddress = "registry.example.com/project"

	const (
		amd64Hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		arm64Hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		indexHex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)

	newStorage := func(stub *orphanedArtifactsRegistryStub) *RepoStagesStorage {
		return NewRepoStagesStorage(&NewRepoStagesStorageOptions{
			RepoAddress:    repoAddress,
			DockerRegistry: stub,
			SkipMetaCheck:  true,
		})
	}

	It("reports per-platform fallback tags whose platform manifests are gone", func() {
		stub := &orphanedArtifactsRegistryStub{
			tags: []string{
				"sha256-" + amd64Hex,
				"sha256-" + arm64Hex,
				"sha256-" + indexHex,
				"regular-stage-tag",
			},
			existingDigests: map[string]bool{},
		}

		orphans, err := newStorage(stub).GetOrphanedArtifactNames(context.Background())

		Expect(err).NotTo(HaveOccurred())
		Expect(orphans).To(ConsistOf(
			repoAddress+":sha256-"+amd64Hex,
			repoAddress+":sha256-"+arm64Hex,
			repoAddress+":sha256-"+indexHex,
		))
	})

	It("keeps per-platform fallback tags whose platform manifests still exist", func() {
		stub := &orphanedArtifactsRegistryStub{
			tags: []string{
				"sha256-" + amd64Hex,
				"sha256-" + arm64Hex,
			},
			existingDigests: map[string]bool{
				repoAddress + "@sha256:" + arm64Hex: true,
			},
		}

		orphans, err := newStorage(stub).GetOrphanedArtifactNames(context.Background())

		Expect(err).NotTo(HaveOccurred())
		Expect(orphans).To(ConsistOf(repoAddress + ":sha256-" + amd64Hex))
	})

	It("ignores non-fallback tags entirely", func() {
		stub := &orphanedArtifactsRegistryStub{
			tags:            []string{"v1.2.3", "latest", "stage-digest-1234567"},
			existingDigests: map[string]bool{},
		}

		orphans, err := newStorage(stub).GetOrphanedArtifactNames(context.Background())

		Expect(err).NotTo(HaveOccurred())
		Expect(orphans).To(BeEmpty())
	})
})
