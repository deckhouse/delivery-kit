package image

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseRef", func() {
	DescribeTable("reference forms",
		func(ref, expectedRepository, expectedTag, expectedDigest string) {
			repository, tag, digest := ParseRef(ref)
			Expect(repository).To(Equal(expectedRepository))
			Expect(tag).To(Equal(expectedTag))
			Expect(digest).To(Equal(expectedDigest))
		},
		Entry("repository only",
			"registry.example.com/app",
			"registry.example.com/app", "", ""),
		Entry("repository and tag",
			"registry.example.com/app:v1.2.3",
			"registry.example.com/app", "v1.2.3", ""),
		Entry("repository and digest",
			"registry.example.com/app@sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739",
			"registry.example.com/app", "", "sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739"),
		Entry("repository, tag and digest",
			"registry.example.com/app:v1.2.3@sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739",
			"registry.example.com/app", "v1.2.3", "sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739"),
		Entry("registry with port, no tag",
			"localhost:5000/app",
			"localhost:5000/app", "", ""),
		Entry("registry with port and tag",
			"localhost:5000/app:v1",
			"localhost:5000/app", "v1", ""),
		Entry("registry with port and digest",
			"localhost:5000/app@sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739",
			"localhost:5000/app", "", "sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739"),
		Entry("short name with tag",
			"alpine:3.20",
			"alpine", "3.20", ""),
		Entry("short name only",
			"alpine",
			"alpine", "", ""),
	)
})

var _ = Describe("ParseRepositoryAndTag", func() {
	DescribeTable("digest is stripped from both repository and tag",
		func(ref, expectedRepository, expectedTag string) {
			repository, tag := ParseRepositoryAndTag(ref)
			Expect(repository).To(Equal(expectedRepository))
			Expect(tag).To(Equal(expectedTag))
		},
		Entry("repository and tag",
			"registry.example.com/app:v1", "registry.example.com/app", "v1"),
		Entry("repository and digest",
			"registry.example.com/app@sha256:55f867c1fdc3df868f2954f1e294c1ed2d4d3048d772b4a3d312b6f94e95d739",
			"registry.example.com/app", ""),
	)
})
