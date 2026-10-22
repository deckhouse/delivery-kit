package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
)

var _ = Describe("stageBuildOptions", func() {
	signStage := func() stage.Interface {
		options := signing.NewFilesSigningOptions("cert", &signing.Signer{})
		options.Enabled = true

		s := stage.GenerateSignFilesAfterInstallStage(
			&config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", After: "install"}}},
			options,
			&stage.BaseStageOptions{},
		)
		Expect(s).NotTo(BeNil())
		return s
	}

	It("keeps a stage that pins its network closed even when the build asks for another one", func() {
		opts := stageBuildOptions(container_backend.BuildOptions{Network: "bridge"}, "linux/amd64", signStage())

		Expect(opts.Network).To(Equal("none"), "--backend-network must not open up a stage that signs files")
		Expect(opts.TargetPlatform).To(Equal("linux/amd64"))
	})

	It("leaves the build network alone for a stage that pins nothing", func() {
		plain := stage.NewBaseStage("install", &stage.BaseStageOptions{})

		opts := stageBuildOptions(container_backend.BuildOptions{Network: "bridge"}, "linux/amd64", plain)

		Expect(opts.Network).To(Equal("bridge"))
	})
})
