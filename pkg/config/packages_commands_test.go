package config

import (
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
})
