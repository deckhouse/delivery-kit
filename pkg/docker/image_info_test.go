package docker

import (
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewInfoFromInspect", func() {
	const digest = "sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739"

	newInspect := func(repoDigests ...string) *types.ImageInspect {
		return &types.ImageInspect{
			ID:          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			RepoDigests: repoDigests,
			Created:     "2026-01-01T00:00:00Z",
			Config:      &container.Config{},
		}
	}

	It("should resolve the repo digest from a by-digest reference", func() {
		info := NewInfoFromInspect("registry.example.com/app@"+digest, newInspect())

		Expect(info.Repository).To(Equal("registry.example.com/app"))
		Expect(info.Tag).To(BeEmpty())
		Expect(info.RepoDigest).To(Equal("registry.example.com/app@" + digest))
		Expect(info.GetDigest()).To(Equal(digest))
	})

	It("should resolve the repo digest of a tagged reference from inspect data", func() {
		info := NewInfoFromInspect("registry.example.com/app:v1", newInspect("registry.example.com/app@"+digest))

		Expect(info.Repository).To(Equal("registry.example.com/app"))
		Expect(info.Tag).To(Equal("v1"))
		Expect(info.GetDigest()).To(Equal(digest))
	})
})
