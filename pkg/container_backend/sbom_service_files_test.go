package container_backend

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func expectedSSHMountPoint() string {
	if runtime.GOOS == "darwin" {
		return "/run/host-services/ssh-auth.sock"
	}
	return "/.werf/tmp/ssh-auth-sock"
}

func TestBuildStapelStageOptions_SBOMServiceFiles(t *testing.T) {
	ctx := context.Background()

	t.Run("nothing mounted by werf lists nothing, even if a user volume names the ssh target", func(t *testing.T) {
		opts := &BuildStapelStageOptions{}
		opts.AddBuildVolumes("/host/sock:/.werf/tmp/ssh-auth-sock", "/host/dir:/.werf/scripts")
		opts.AddVolumes([]string{"/host/other:/.werf/tmp/ssh-auth-sock"})
		assert.Empty(t, opts.SBOMServiceFiles(ctx))
	})

	t.Run("an empty agent socket mounts and lists nothing", func(t *testing.T) {
		opts := &BuildStapelStageOptions{}
		opts.MountSSHAgentSocket("")
		assert.Empty(t, opts.SBOMServiceFiles(ctx))
		assert.Empty(t, opts.BuildVolumes)
	})

	t.Run("a real ssh agent mount lists its exact destination", func(t *testing.T) {
		opts := &BuildStapelStageOptions{}
		opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
		assert.Equal(t, []string{expectedSSHMountPoint()}, opts.SBOMServiceFiles(ctx))
	})

	t.Run("commands list the script file of the native backend", func(t *testing.T) {
		opts := &BuildStapelStageOptions{}
		assert.Empty(t, opts.SBOMServiceFiles(ctx))
		opts.AddCommands("true")
		assert.Equal(t, []string{"/.werf/script.sh"}, opts.SBOMServiceFiles(ctx))
		assert.Equal(t, "/.werf/script.sh", ServiceScriptPath)
	})

	t.Run("user volumes, directories and run options do not extend the list", func(t *testing.T) {
		opts := &BuildStapelStageOptions{}
		opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
		opts.AddCommands("true")
		opts.AddBuildVolumes("/host/cache:/.werf/user", "/host/x:/go-cache")
		opts.AddVolumes([]string{"/data"})
		opts.AddEnvs(map[string]string{"A": "1"})
		assert.Equal(t, []string{expectedSSHMountPoint(), "/.werf/script.sh"}, opts.SBOMServiceFiles(ctx))
	})

	t.Run("a copy of the options (as the builder makes) keeps the provenance", func(t *testing.T) {
		opts := BuildStapelStageOptions{}
		opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
		final := opts
		assert.Equal(t, []string{expectedSSHMountPoint()}, final.SBOMServiceFiles(ctx))
	})

	t.Run("the result is a fresh slice: changing it does not change the provenance", func(t *testing.T) {
		opts := &BuildStapelStageOptions{}
		opts.MountSSHAgentSocket("/run/user/1000/agent.sock")
		opts.AddCommands("true")
		got := opts.SBOMServiceFiles(ctx)
		got[0] = "/.werf/tampered"
		assert.Equal(t, []string{expectedSSHMountPoint(), "/.werf/script.sh"}, opts.SBOMServiceFiles(ctx))
	})
}

func TestLegacyStageImageContainer_SBOMServiceFiles(t *testing.T) {
	ctx := context.Background()
	newImage := func() *LegacyStageImage { return NewLegacyStageImage(nil, "repo:tag", nil, "") }

	t.Run("a user volume on the ssh target is not provenance", func(t *testing.T) {
		img := newImage()
		img.BuilderContainer().AddVolume("/host/sock:/.werf/tmp/ssh-auth-sock")
		img.BuilderContainer().AddVolume("/host/shell:/.werf/shell")
		assert.Empty(t, img.container.SBOMServiceFiles(ctx))
	})

	t.Run("an empty agent socket lists nothing", func(t *testing.T) {
		img := newImage()
		img.BuilderContainer().MountSSHAgentSocket("")
		assert.Empty(t, img.container.SBOMServiceFiles(ctx))
	})

	t.Run("a real ssh agent mount lists its exact destination once", func(t *testing.T) {
		img := newImage()
		img.BuilderContainer().MountSSHAgentSocket("/run/user/1000/agent.sock")
		img.BuilderContainer().MountSSHAgentSocket("/run/user/1000/agent.sock")
		assert.Equal(t, []string{expectedSSHMountPoint()}, img.container.SBOMServiceFiles(ctx))
	})

	t.Run("run commands and the shell directory do not declare script.sh", func(t *testing.T) {
		img := newImage()
		img.BuilderContainer().AddRunCommands("true")
		img.BuilderContainer().AddVolume("/host/shell:/.werf/shell")
		assert.Empty(t, img.container.SBOMServiceFiles(ctx))
	})

	t.Run("the result is a fresh slice", func(t *testing.T) {
		img := newImage()
		img.BuilderContainer().MountSSHAgentSocket("/run/user/1000/agent.sock")
		img.container.SBOMServiceFiles(ctx)[0] = "/.werf/tampered"
		assert.Equal(t, []string{expectedSSHMountPoint()}, img.container.SBOMServiceFiles(ctx))
	})
}
