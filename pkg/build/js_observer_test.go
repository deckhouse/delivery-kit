package build

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/builder"
	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
)

type jsObserverLegacyStageBuilder struct {
	stage_builder.StageBuilderInterface
	container *jsObserverLegacyContainer
}

func (b *jsObserverLegacyStageBuilder) LegacyStapelStageBuilder() stage_builder.LegacyStapelStageBuilderInterface {
	return jsObserverLegacyStapelBuilder{container: b.container}
}

type jsObserverLegacyStapelBuilder struct {
	stage_builder.LegacyStapelStageBuilderInterface
	container *jsObserverLegacyContainer
}

func (b jsObserverLegacyStapelBuilder) BuilderContainer() container_backend.LegacyBuilderContainer {
	return b.container
}

// Any call to a method that is not overridden, such as adding an environment
// variable, panics through the nil embedded interface.
type jsObserverLegacyContainer struct {
	container_backend.LegacyBuilderContainer
	volumes         []string
	serviceCommands []string
}

func (c *jsObserverLegacyContainer) AddVolume(volumes ...string) {
	c.volumes = append(c.volumes, volumes...)
}

func (c *jsObserverLegacyContainer) AddServiceRunCommands(commands ...string) {
	c.serviceCommands = append(c.serviceCommands, commands...)
}

func (c *jsObserverLegacyContainer) MountSSHAgentSocket(string) {}

func sbomConveyor(enabled bool) *Conveyor {
	return &Conveyor{werfConfig: &config.WerfConfig{Meta: &config.Meta{Build: config.MetaBuild{Sbom: &config.MetaBuildSbom{Enable: enabled}}}}}
}

func userShell(tmpDir string) *builder.Shell {
	return builder.NewShellBuilder(&config.Shell{Install: []string{"npm run build"}, Packages: []string{"npm ci"}}, &builder.Extra{ContainerWerfPath: "/.werf", TmpPath: tmpDir}, nil, "")
}

var _ = Describe("JavaScript bundle observer in Stapel stages", func() {
	stapelImage := &image.Image{StapelImageConfig: &config.StapelImage{}}
	dockerfileImage := &image.Image{}

	DescribeTable("runs only in SBOM-enabled Stapel user stages",
		func(conveyor *Conveyor, img *image.Image, stageName stage.StageName, expected string) {
			stg := stage.NewBaseStage(stageName, &stage.BaseStageOptions{})
			Expect(jsObserverInstrumentation(conveyor, img, stg)).To(Equal(expected))
		},
		Entry("install with SBOM", sbomConveyor(true), stapelImage, stage.Install, jsobserver.InstrumentationVersion),
		Entry("setup with SBOM", sbomConveyor(true), stapelImage, stage.Setup, jsobserver.InstrumentationVersion),
		Entry("install without SBOM", sbomConveyor(false), stapelImage, stage.Install, ""),
		Entry("packages installation", sbomConveyor(true), stapelImage, stage.Packages, jsobserver.InstrumentationVersion),
		Entry("git archive", sbomConveyor(true), stapelImage, stage.GitArchive, ""),
		Entry("Dockerfile image", sbomConveyor(true), dockerfileImage, stage.Install, ""),
	)

	It("keeps the digest of a stage without the observer and changes it with the observer", func(ctx SpecContext) {
		conveyor := sbomConveyor(false)
		without, err := calculateDigest(ctx, "install", "deps", nil, conveyor, calculateDigestOptions{})
		Expect(err).To(Succeed())
		Expect(without).To(Equal(util.Sha3_224Hash("", "install", "deps")))

		with, err := calculateDigest(ctx, "install", "deps", nil, conveyor, calculateDigestOptions{JSObserver: jsobserver.InstrumentationVersion})
		Expect(err).To(Succeed())
		Expect(with).NotTo(Equal(without))

		anchor := calculateDigestOptions{Anchor: true, HolisticInputs: []string{"input"}}
		anchorWithout, err := calculateDigest(ctx, "anchor", "", nil, conveyor, anchor)
		Expect(err).To(Succeed())
		anchor.JSObserver = jsobserver.InstrumentationVersion
		anchorWith, err := calculateDigest(ctx, "anchor", "", nil, conveyor, anchor)
		Expect(err).To(Succeed())
		Expect(anchorWith).NotTo(Equal(anchorWithout))
	})

	It("changes the anchor of an image only when one of its stages runs the observer", func() {
		img := &image.Image{StapelImageConfig: &config.StapelImage{}}
		img.SetStages([]stage.Interface{stage.NewBaseStage(stage.From, &stage.BaseStageOptions{}), stage.NewBaseStage(stage.GitArchive, &stage.BaseStageOptions{})})
		Expect(jsObserverImageInstrumentation(sbomConveyor(true), img)).To(BeEmpty())

		img.SetStages(append(img.GetStages(), stage.NewBaseStage(stage.Setup, &stage.BaseStageOptions{})))
		Expect(jsObserverImageInstrumentation(sbomConveyor(true), img)).To(Equal(jsobserver.InstrumentationVersion))
		Expect(jsObserverImageInstrumentation(sbomConveyor(false), img)).To(BeEmpty())
	})

	DescribeTable("mounts the observer read-only and exports NODE_OPTIONS before the Buildah stage commands",
		func(ctx context.Context, run func(context.Context, *builder.Shell, stage_builder.StageBuilderInterface) error, userCommand string) {
			stageBuilder := stage_builder.NewStageBuilder(nil, "", nil)

			attachJSObserver(stageBuilder, false, "/host/assets")
			Expect(run(ctx, userShell(GinkgoT().TempDir()), stageBuilder)).To(Succeed())

			opts := stageBuilder.GetStapelStageBuilderImplementation().BuildStapelStageOptions
			Expect(opts.Commands).To(Equal([]string{jsObserverNodeOptionsExport(jsObserverContainerDir), userCommand}))
			Expect(opts.BuildVolumes).To(Equal([]string{"/host/assets:/.werf/js-observer:ro"}))
			Expect(opts.Envs).To(BeEmpty())
			Expect(opts.BuildTimeEnvs).To(BeEmpty())
		},
		Entry("install", func(ctx context.Context, shell *builder.Shell, stageBuilder stage_builder.StageBuilderInterface) error {
			return shell.Install(ctx, nil, stageBuilder, false)
		}, "npm run build"),
		Entry("packages, whose lifecycle scripts may bundle", func(ctx context.Context, shell *builder.Shell, stageBuilder stage_builder.StageBuilderInterface) error {
			return shell.Packages(ctx, nil, stageBuilder, false)
		}, "npm ci"),
	)

	It("mounts the observer read-only and exports NODE_OPTIONS before the legacy stage script", func(ctx SpecContext) {
		container := &jsObserverLegacyContainer{}
		stageBuilder := &jsObserverLegacyStageBuilder{container: container}

		attachJSObserver(stageBuilder, true, "/host/assets")
		Expect(userShell(GinkgoT().TempDir()).Install(ctx, nil, stageBuilder, true)).To(Succeed())

		Expect(container.serviceCommands).To(Equal([]string{jsObserverNodeOptionsExport(jsObserverContainerDir), "/.werf/shell/script.sh"}))
		Expect(container.volumes).To(ContainElement("/host/assets:/.werf/js-observer:ro"))
	})

	It("prepares an observer directory every container user can read", func(ctx SpecContext) {
		dir, err := prepareJSObserverAssets(ctx, filepath.Join(GinkgoT().TempDir(), "conveyor"))
		Expect(err).To(Succeed())

		info, err := os.Stat(dir)
		Expect(err).To(Succeed())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o755)))
		Expect(filepath.Join(dir, jsobserver.BootstrapFileName)).To(BeAnExistingFile())
	})

	DescribeTable("extends NODE_OPTIONS of the environment and leaves later user settings in force",
		func(ctx context.Context, inherited, userCommand, expectedSuffix string, observed bool) {
			if _, err := exec.LookPath("node"); err != nil {
				Skip("node is not installed")
			}
			assetsDir, err := prepareJSObserverAssets(ctx, GinkgoT().TempDir())
			Expect(err).To(Succeed())

			script := strings.Join([]string{
				jsObserverNodeOptionsExport(assetsDir),
				userCommand,
				// The probe runs in a child Node.js process, as npm runs lifecycle scripts.
				`node -e 'require("node:child_process").execFileSync(process.execPath, ["-e", "console.log(Boolean(globalThis[Symbol.for(\"werf.jsObserver\")]) + \" \" + process.env.NODE_OPTIONS)"], { stdio: "inherit" })'`,
			}, "\n")
			cmd := exec.CommandContext(ctx, "sh", "-ec", script)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			if inherited != "" {
				cmd.Env = append(cmd.Env, "NODE_OPTIONS="+inherited)
			}
			output, err := cmd.CombinedOutput()
			Expect(err).To(Succeed(), string(output))

			bootstrap := "--require " + filepath.Join(assetsDir, jsobserver.BootstrapFileName)
			expected := strings.TrimSpace(strings.Join([]string{bootstrap, expectedSuffix}, " "))
			if !observed {
				expected = expectedSuffix
			}
			Expect(strings.TrimSpace(string(output))).To(Equal(fmt.Sprintf("%t %s", observed, expected)))
		},
		Entry("no NODE_OPTIONS in the base image", "", ":", "", true),
		Entry("NODE_OPTIONS of the base image", "--max-old-space-size=128", ":", "--max-old-space-size=128", true),
		Entry("NODE_OPTIONS extended by the user", "--max-old-space-size=128", `export NODE_OPTIONS="$NODE_OPTIONS --no-warnings"`, "--max-old-space-size=128 --no-warnings", true),
		Entry("NODE_OPTIONS replaced by the user", "--max-old-space-size=128", `export NODE_OPTIONS="--no-warnings"`, "--no-warnings", false),
	)
})
