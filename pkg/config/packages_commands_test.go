package config

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ContainerFactoryVersionSnapshotCmd", func() {
	cmd := ContainerFactoryVersionSnapshotCmd()

	It("keeps the hard PACKAGES_VERSION guard for SBOM provenance", func() {
		Expect(cmd).To(ContainSubstring(`${PACKAGES_VERSION:?required by werf for pm SBOM provenance}`))
	})

	It("writes the snapshot to the container-factory-version file", func() {
		Expect(cmd).To(ContainSubstring(ContainerFactoryVersionFile))
	})

	DescribeTable("resolves pm env vars from build secrets mounted under /run/secrets",
		func(envName string) {
			Expect(cmd).To(ContainSubstring(
				`export ` + envName + `="${` + envName + `:-$(cat /run/secrets/` + envName + ` 2>/dev/null || true)}"`,
			))
		},

		Entry("PACKAGES_VERSION from secret", "PACKAGES_VERSION"),
		Entry("REGISTRY from secret", "REGISTRY"),
	)

	It("resolves env vars before the guard so pm sync inherits them", func() {
		guardIdx := strings.Index(cmd, `${PACKAGES_VERSION:?`)
		versionExportIdx := strings.Index(cmd, `export PACKAGES_VERSION=`)
		registryExportIdx := strings.Index(cmd, `export REGISTRY=`)

		Expect(versionExportIdx).To(BeNumerically(">=", 0))
		Expect(registryExportIdx).To(BeNumerically(">=", 0))
		Expect(versionExportIdx).To(BeNumerically("<", guardIdx))
		Expect(registryExportIdx).To(BeNumerically("<", guardIdx))
	})
})
