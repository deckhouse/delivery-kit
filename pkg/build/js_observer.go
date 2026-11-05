package build

import (
	"context"
	"fmt"
	"os"
	"path"
	"slices"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
)

const jsObserverContainerDir = "/.werf/js-observer"

// Packages is included because lifecycle scripts of installed packages may
// bundle during the installation.
var jsObserverStageNames = []stage.StageName{stage.BeforeInstall, stage.Packages, stage.Install, stage.BeforeSetup, stage.Setup}

func jsObserverInstrumentation(conveyor *Conveyor, img *image.Image, stg stage.Interface) string {
	if conveyor == nil || !conveyor.EnableSbom() || img.StapelImageConfig == nil || !slices.Contains(jsObserverStageNames, stg.Name()) {
		return ""
	}
	return jsobserver.InstrumentationVersion
}

// The content anchor stands for the whole image, so it changes with the
// observer whenever any stage of the image runs it.
func jsObserverImageInstrumentation(conveyor *Conveyor, img *image.Image) string {
	for _, stg := range img.GetStages() {
		if instrumentation := jsObserverInstrumentation(conveyor, img, stg); instrumentation != "" {
			return instrumentation
		}
	}
	return ""
}

// The observer is enabled from the stage script rather than through the
// container environment, so NODE_OPTIONS of the base image is extended instead
// of replaced, and nothing of it reaches the committed image config.
func jsObserverNodeOptionsExport(assetsDir string) string {
	return fmt.Sprintf(`export NODE_OPTIONS="--require %s${NODE_OPTIONS:+ $NODE_OPTIONS}"`, path.Join(assetsDir, jsobserver.BootstrapFileName))
}

func prepareJSObserverAssets(ctx context.Context, tmpDir string) (string, error) {
	if err := os.MkdirAll(tmpDir, 0o775); err != nil {
		return "", fmt.Errorf("create %s: %w", tmpDir, err)
	}
	dir, err := os.MkdirTemp(tmpDir, "js-observer-")
	if err != nil {
		return "", fmt.Errorf("create JavaScript observer directory: %w", err)
	}
	// Commands of the stage may run Node.js as a non-root user.
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := jsobserver.WriteAssets(ctx, dir); err != nil {
		return "", err
	}
	return dir, nil
}

// attachJSObserver must run before the stage adds its own commands, so that
// they inherit the exported NODE_OPTIONS.
func attachJSObserver(stageBuilder stage_builder.StageBuilderInterface, useLegacyStapelBuilder bool, hostAssetsDir string) {
	volume := fmt.Sprintf("%s:%s:ro", hostAssetsDir, jsObserverContainerDir)
	command := jsObserverNodeOptionsExport(jsObserverContainerDir)
	if useLegacyStapelBuilder {
		container := stageBuilder.LegacyStapelStageBuilder().BuilderContainer()
		container.AddVolume(volume)
		container.AddServiceRunCommands(command)
		return
	}
	stageBuilder.StapelStageBuilder().AddBuildVolumes(volume)
	stageBuilder.StapelStageBuilder().AddCommands(command)
}
