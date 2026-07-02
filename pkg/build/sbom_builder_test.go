package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	werfImage "github.com/werf/werf/v2/pkg/image"
)

var _ = Describe("Builder image classification", func() {
	Describe("isGolangBuilderImage()", func() {
		DescribeTable("should detect golang builder images from container-factory registry",
			func(name string, expected bool) {
				Expect(isGolangBuilderImage(name)).To(Equal(expected))
			},
			// Golang images: must return true
			Entry("golang-alpine with tag", "registry.deckhouse.io/container-factory/builder/golang-alpine:1.25", true),
			Entry("golang-alt with tag", "registry.deckhouse.io/container-factory/builder/golang-alt:1.25", true),
			Entry("golang-debian with tag", "registry.deckhouse.io/container-factory/builder/golang-debian:1.25", true),
			Entry("golang-wolfi with tag", "registry.deckhouse.io/container-factory/builder/golang-wolfi:1.25", true),
			Entry("golang plain with tag", "registry.deckhouse.io/container-factory/builder/golang:1.26", true),
			Entry("golang-artifact with tag", "registry.deckhouse.io/container-factory/builder/golang-artifact:1.26", true),
			Entry("golang with digest", "registry.deckhouse.io/container-factory/builder/golang@sha256:abc123", true),
			Entry("golang without tag", "registry.deckhouse.io/container-factory/builder/golang", true),

			// Alpine images: must return false (not golang)
			Entry("alpine (not golang)", "registry.deckhouse.io/container-factory/builder/alpine:3.22", false),
			Entry("alpine-svace (not golang)", "registry.deckhouse.io/container-factory/builder/alpine-svace:3.22", false),
			Entry("alpine with digest (not golang)", "registry.deckhouse.io/container-factory/builder/alpine@sha256:abc123", false),

			// Node images: must return false
			Entry("node-alpine (not golang)", "registry.deckhouse.io/container-factory/builder/node-alpine:22.22", false),

			// Other builder images from container-factory: must return false
			Entry("scratch builder", "registry.deckhouse.io/container-factory/builder/scratch", false),
			Entry("wolfi builder", "registry.deckhouse.io/container-factory/builder/wolfi", false),
			Entry("distroless builder", "registry.deckhouse.io/container-factory/builder/distroless", false),

			// Images from other namespaces: must return false
			Entry("werf registry golang image", "registry.werf.io/base/golang:1.12-alpine3.9", false),
			Entry("docker.io image", "docker.io/namespace/repo:builder-tag", false),
			Entry("docker hub library", "docker.io/library/golang:1.21", false),

			// Edge cases
			Entry("empty string", "", false),
			Entry("just a path without registry", "builder/golang:1.26", false),
			Entry("path with golang substring but different registry", "example.com/container-factory/builder/golang:1.0", false),
		)

		It("should reject image where golang appears as substring in the registry name", func() {
			Expect(isGolangBuilderImage("registry.deckhouse.io/container-factory-builder-golang/other:1.0")).To(BeFalse())
		})
	})

	Describe("isAlpineBuilderImage()", func() {
		DescribeTable("should detect alpine builder images from container-factory registry",
			func(name string, expected bool) {
				Expect(isAlpineBuilderImage(name)).To(Equal(expected))
			},
			// Alpine images: must return true
			Entry("alpine with tag", "registry.deckhouse.io/container-factory/builder/alpine:3.22", true),
			Entry("alpine-svace with tag", "registry.deckhouse.io/container-factory/builder/alpine-svace:3.22", true),
			Entry("alpine with digest", "registry.deckhouse.io/container-factory/builder/alpine@sha256:abc123", true),
			Entry("alpine without tag", "registry.deckhouse.io/container-factory/builder/alpine", true),

			// Golang-alpine: must return false (starts with builder/golang, not builder/alpine)
			Entry("golang-alpine (not alpine builder)", "registry.deckhouse.io/container-factory/builder/golang-alpine:1.25", false),

			// Node-alpine: must return false (starts with builder/node, not builder/alpine)
			Entry("node-alpine (not alpine builder)", "registry.deckhouse.io/container-factory/builder/node-alpine:22.22", false),

			// Other golang images: must return false
			Entry("golang (not alpine)", "registry.deckhouse.io/container-factory/builder/golang:1.26", false),
			Entry("golang-debian (not alpine)", "registry.deckhouse.io/container-factory/builder/golang-debian:1.26", false),

			// Other builder images from container-factory: must return false
			Entry("scratch builder", "registry.deckhouse.io/container-factory/builder/scratch", false),
			Entry("wolfi builder", "registry.deckhouse.io/container-factory/builder/wolfi", false),
			Entry("distroless builder", "registry.deckhouse.io/container-factory/builder/distroless", false),

			// Images from other namespaces: must return false
			Entry("werf registry alpine image", "registry.werf.io/base/alpine:3.18", false),
			Entry("docker.io image", "docker.io/namespace/repo:alpine", false),

			// Edge cases
			Entry("empty string", "", false),
			Entry("just a path without registry", "builder/alpine:3.18", false),
			Entry("alpine under different registry", "example.com/container-factory/builder/alpine:1.0", false),
		)
	})

	Describe("isTrustedBuilderImage()", func() {
		DescribeTable("should detect trusted builder images by label",
			func(labels map[string]string, expected bool) {
				Expect(isTrustedBuilderImage(labels)).To(Equal(expected))
			},
			Entry("nil labels", nil, false),
			Entry("empty labels", map[string]string{}, false),
			Entry("label set to false", map[string]string{werfImage.DeckhouseInternalBuilderLabel: "false"}, false),
			Entry("label set to true", map[string]string{werfImage.DeckhouseInternalBuilderLabel: "true"}, true),
			Entry("case-sensitive label mismatch", map[string]string{"io.deckhouse.internal.builder": "True"}, false),
			Entry("other labels without builder", map[string]string{"foo": "bar", "baz": "qux"}, false),
			Entry("other labels with builder true", map[string]string{"foo": "bar", werfImage.DeckhouseInternalBuilderLabel: "true", "baz": "qux"}, true),
			Entry("value is non-empty but not true", map[string]string{werfImage.DeckhouseInternalBuilderLabel: "yes"}, false),
		)
	})
})
