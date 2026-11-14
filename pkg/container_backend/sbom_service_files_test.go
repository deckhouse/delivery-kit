package container_backend

import (
	"context"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("SBOM service files of the stage builders", func() {
	ctx := context.Background()

	ginkgo.Describe("native stapel stage options", func() {
		ginkgo.It("lists nothing when werf mounted nothing, even if a user volume names the ssh target", func() {
			opts := &BuildStapelStageOptions{}
			opts.AddBuildVolumes("/host/sock:/.werf/tmp/ssh-auth-sock", "/host/dir:/.werf/scripts")
			opts.AddVolumes([]string{"/host/other:/.werf/tmp/ssh-auth-sock"})
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.BeEmpty())
		})

		ginkgo.It("mounts and lists nothing for an empty agent socket", func() {
			opts := &BuildStapelStageOptions{}
			opts.MountSSHAgentSocket("")
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.BeEmpty())
			gomega.Expect(opts.BuildVolumes).To(gomega.BeEmpty())
		})

		ginkgo.It("lists the exact destination of a real ssh agent mount", func() {
			opts := &BuildStapelStageOptions{}
			opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{expectedSSHMountPoint()}))
		})

		ginkgo.It("lists the script file only when there are commands", func() {
			opts := &BuildStapelStageOptions{}
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.BeEmpty())
			opts.AddCommands("true")
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{"/.werf/script.sh"}))
			gomega.Expect(ServiceScriptPath).To(gomega.Equal("/.werf/script.sh"))
		})

		ginkgo.It("is not extended by user volumes, directories or run options", func() {
			opts := &BuildStapelStageOptions{}
			opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
			opts.AddCommands("true")
			opts.AddBuildVolumes("/host/cache:/.werf/user", "/host/x:/go-cache")
			opts.AddVolumes([]string{"/data"})
			opts.AddEnvs(map[string]string{"A": "1"})
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{expectedSSHMountPoint(), "/.werf/script.sh"}))
		})

		ginkgo.It("keeps the provenance in a copy of the options, as the builder makes", func() {
			opts := BuildStapelStageOptions{}
			opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
			final := opts
			gomega.Expect(final.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{expectedSSHMountPoint()}))
		})

		ginkgo.It("returns a fresh slice: changing it does not change the provenance", func() {
			opts := &BuildStapelStageOptions{}
			opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
			opts.AddCommands("true")
			opts.SBOMServiceFiles(ctx)[0] = "/.werf/tampered"
			gomega.Expect(opts.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{expectedSSHMountPoint(), "/.werf/script.sh"}))
		})
	})

	ginkgo.Describe("legacy stage image container", func() {
		var img *LegacyStageImage

		ginkgo.BeforeEach(func() {
			img = NewLegacyStageImage(nil, "repo:tag", nil, "")
		})

		ginkgo.It("does not treat a user volume on the ssh target as provenance", func() {
			img.BuilderContainer().AddVolume("/host/sock:/.werf/tmp/ssh-auth-sock")
			img.BuilderContainer().AddVolume("/host/shell:/.werf/shell")
			gomega.Expect(img.container.SBOMServiceFiles(ctx)).To(gomega.BeEmpty())
		})

		ginkgo.It("lists nothing for an empty agent socket", func() {
			img.BuilderContainer().MountSSHAgentSocket("")
			gomega.Expect(img.container.SBOMServiceFiles(ctx)).To(gomega.BeEmpty())
		})

		ginkgo.It("lists the exact destination of a real ssh agent mount once", func() {
			img.BuilderContainer().MountSSHAgentSocket("/run/user/1000/agent.sock")
			img.BuilderContainer().MountSSHAgentSocket("/run/user/1000/agent.sock")
			gomega.Expect(img.container.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{expectedSSHMountPoint()}))
		})

		ginkgo.It("does not declare script.sh for run commands or the shell directory", func() {
			img.BuilderContainer().AddRunCommands("true")
			img.BuilderContainer().AddVolume("/host/shell:/.werf/shell")
			gomega.Expect(img.container.SBOMServiceFiles(ctx)).To(gomega.BeEmpty())
		})

		ginkgo.It("returns a fresh slice", func() {
			img.BuilderContainer().MountSSHAgentSocket("/run/user/1000/agent.sock")
			img.container.SBOMServiceFiles(ctx)[0] = "/.werf/tampered"
			gomega.Expect(img.container.SBOMServiceFiles(ctx)).To(gomega.Equal([]string{expectedSSHMountPoint()}))
		})
	})
})
