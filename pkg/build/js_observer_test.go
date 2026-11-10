package build

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/builder"
	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
)

var _ = ginkgo.Describe("JavaScript bundle observer in Stapel stages", func() {
	stapelImage := &image.Image{StapelImageConfig: &config.StapelImage{}}
	dockerfileImage := &image.Image{}

	ginkgo.DescribeTable("runs only in SBOM-enabled Stapel user stages",
		func(conveyor *Conveyor, img *image.Image, stageName stage.StageName, expected string) {
			stg := stage.NewBaseStage(stageName, &stage.BaseStageOptions{})
			gomega.Expect(jsObserverInstrumentation(conveyor, img, stg)).To(gomega.Equal(expected))
		},
		ginkgo.Entry("before install with SBOM", sbomConveyor(true), stapelImage, stage.BeforeInstall, jsobserver.InstrumentationVersion),
		ginkgo.Entry("install with SBOM", sbomConveyor(true), stapelImage, stage.Install, jsobserver.InstrumentationVersion),
		ginkgo.Entry("before setup with SBOM", sbomConveyor(true), stapelImage, stage.BeforeSetup, jsobserver.InstrumentationVersion),
		ginkgo.Entry("setup with SBOM", sbomConveyor(true), stapelImage, stage.Setup, jsobserver.InstrumentationVersion),
		ginkgo.Entry("install without SBOM", sbomConveyor(false), stapelImage, stage.Install, ""),
		ginkgo.Entry("packages installation", sbomConveyor(true), stapelImage, stage.Packages, jsobserver.InstrumentationVersion),
		ginkgo.Entry("git archive", sbomConveyor(true), stapelImage, stage.GitArchive, ""),
		ginkgo.Entry("Dockerfile image", sbomConveyor(true), dockerfileImage, stage.Install, ""),
	)

	ginkgo.It("keeps the digest of a stage without the observer and changes it with the observer", func(ctx ginkgo.SpecContext) {
		conveyor := sbomConveyor(false)
		without, err := calculateDigest(ctx, "install", "deps", nil, conveyor, calculateDigestOptions{})
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(without).To(gomega.Equal(util.Sha3_224Hash("", "install", "deps")))

		with, err := calculateDigest(ctx, "install", "deps", nil, conveyor, calculateDigestOptions{JSObserver: jsobserver.InstrumentationVersion})
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(with).NotTo(gomega.Equal(without))

		anchor := calculateDigestOptions{Anchor: true, HolisticInputs: []string{"input"}}
		anchorWithout, err := calculateDigest(ctx, "anchor", "", nil, conveyor, anchor)
		gomega.Expect(err).To(gomega.Succeed())
		anchor.JSObserver = jsobserver.InstrumentationVersion
		anchorWith, err := calculateDigest(ctx, "anchor", "", nil, conveyor, anchor)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(anchorWith).NotTo(gomega.Equal(anchorWithout))
	})

	ginkgo.It("changes the anchor of an image only when one of its stages runs the observer", func() {
		img := &image.Image{StapelImageConfig: &config.StapelImage{}}
		img.SetStages([]stage.Interface{stage.NewBaseStage(stage.From, &stage.BaseStageOptions{}), stage.NewBaseStage(stage.GitArchive, &stage.BaseStageOptions{})})
		gomega.Expect(jsObserverImageInstrumentation(sbomConveyor(true), img)).To(gomega.BeEmpty())

		img.SetStages(append(img.GetStages(), stage.NewBaseStage(stage.Setup, &stage.BaseStageOptions{})))
		gomega.Expect(jsObserverImageInstrumentation(sbomConveyor(true), img)).To(gomega.Equal(jsobserver.InstrumentationVersion))
		gomega.Expect(jsObserverImageInstrumentation(sbomConveyor(false), img)).To(gomega.BeEmpty())
	})

	ginkgo.It("changes the content anchor digest of a Stapel image whose stages run the observer", func(ctx ginkgo.SpecContext) {
		anchorDigest := func(stapelImageConfig config.StapelImageInterface) string {
			img, err := image.NewImage(ctx, "linux/amd64", "app", image.NoBaseImage, image.ImageOptions{})
			gomega.Expect(err).To(gomega.Succeed())
			img.StapelImageConfig = stapelImageConfig
			anchor := stage.GenerateVerityAnnotationStage(&stage.BaseStageOptions{TargetPlatform: "linux/amd64"})
			anchor.SetContentAnchor(true)
			img.SetStages([]stage.Interface{newJSObserverStage(stage.Install), anchor})

			phase := &BuildPhase{BasePhase: BasePhase{Conveyor: sbomConveyor(true)}}
			gomega.Expect(phase.calculateAnchorDigest(ctx, img, nil, false)).To(gomega.Succeed())
			return img.GetAnchorDigest()
		}

		gomega.Expect(anchorDigest(&config.StapelImage{StapelImageBase: &config.StapelImageBase{}})).NotTo(gomega.Equal(anchorDigest(nil)))
	})

	ginkgo.It("changes the digest of a Stapel stage that runs the observer", func(ctx ginkgo.SpecContext) {
		stageDigest := func(stapelImageConfig config.StapelImageInterface) string {
			server, _ := newPublicationLockServer()
			phase, img, stg := newPublicationPhase(ctx, &publicationStorageManager{primary: &publicationStorage{}}, server.URL, false, 10)
			phase.Conveyor.werfConfig.Meta.Build.Sbom = &config.MetaBuildSbom{Enable: true}
			img.StapelImageConfig = stapelImageConfig
			reported := &reportedStage{buildableStage: &buildableStage{publicationStage: stg.(*publicationStage)}}

			_, cleanup, err := phase.calculateStage(ctx, img, reported)
			gomega.Expect(err).To(gomega.Succeed())
			cleanup()
			return reported.GetDigest()
		}

		gomega.Expect(stageDigest(&config.StapelImage{})).NotTo(gomega.Equal(stageDigest(nil)))
	})

	ginkgo.DescribeTable("attaches the observer when preparing the instructions of a Stapel stage that runs it",
		func(ctx ginkgo.SpecContext, stageName stage.StageName, sbom, attached bool) {
			conveyor := sbomConveyor(sbom)
			conveyor.ContainerBackend = &publicationContainerBackend{}
			conveyor.giterminismManager = &jsObserverGiterminismManager{}
			conveyor.tmpDir = ginkgo.GinkgoT().TempDir()
			phase := &BuildPhase{BasePhase: BasePhase{Conveyor: conveyor}, StagesIterator: NewStagesIterator(conveyor)}
			img, err := image.NewImage(ctx, "linux/amd64", "app", image.NoBaseImage, image.ImageOptions{})
			gomega.Expect(err).To(gomega.Succeed())
			img.StapelImageConfig = &config.StapelImage{}
			stg := newJSObserverStage(stageName)
			stageBuilder := stage_builder.NewStageBuilder(nil, "", nil)
			stg.SetStageImage(&stage.StageImage{Image: container_backend.NewLegacyStageImage(nil, "stage", nil, "linux/amd64"), Builder: stageBuilder})

			gomega.Expect(phase.prepareStageInstructions(ctx, img, stg)).To(gomega.Succeed())

			opts := stageBuilder.GetStapelStageBuilderImplementation().BuildStapelStageOptions
			if !attached {
				gomega.Expect(opts.Commands).To(gomega.Equal([]string{jsObserverStageCommand}))
				gomega.Expect(opts.BuildVolumes).To(gomega.BeEmpty())
				return
			}
			gomega.Expect(opts.Commands).To(gomega.Equal([]string{jsObserverNodeOptionsExport(jsObserverContainerDir), jsObserverStageCommand}))
			gomega.Expect(opts.BuildVolumes).To(gomega.ConsistOf(gomega.And(gomega.HavePrefix(conveyor.tmpDir), gomega.HaveSuffix(":"+jsObserverContainerDir+":ro"))))
		},
		ginkgo.Entry("install", stage.Install, true, true),
		ginkgo.Entry("setup", stage.Setup, true, true),
		ginkgo.Entry("install without SBOM", stage.Install, false, false),
		ginkgo.Entry("git archive", stage.GitArchive, true, false),
	)

	ginkgo.DescribeTable("mounts the observer read-only and exports NODE_OPTIONS before the Buildah stage commands",
		func(ctx context.Context, run func(context.Context, *builder.Shell, stage_builder.StageBuilderInterface) error, userCommand string) {
			stageBuilder := stage_builder.NewStageBuilder(nil, "", nil)

			attachJSObserver(stageBuilder, false, "/host/assets")
			gomega.Expect(run(ctx, userShell(ginkgo.GinkgoT().TempDir()), stageBuilder)).To(gomega.Succeed())

			opts := stageBuilder.GetStapelStageBuilderImplementation().BuildStapelStageOptions
			gomega.Expect(opts.Commands).To(gomega.Equal([]string{jsObserverNodeOptionsExport(jsObserverContainerDir), userCommand}))
			gomega.Expect(opts.BuildVolumes).To(gomega.Equal([]string{"/host/assets:/.werf/js-observer:ro"}))
			gomega.Expect(opts.Envs).To(gomega.BeEmpty())
			gomega.Expect(opts.BuildTimeEnvs).To(gomega.BeEmpty())
		},
		ginkgo.Entry("install", func(ctx context.Context, shell *builder.Shell, stageBuilder stage_builder.StageBuilderInterface) error {
			return shell.Install(ctx, nil, stageBuilder, false)
		}, "npm run build"),
		ginkgo.Entry("packages, whose lifecycle scripts may bundle", func(ctx context.Context, shell *builder.Shell, stageBuilder stage_builder.StageBuilderInterface) error {
			return shell.Packages(ctx, nil, stageBuilder, false)
		}, "npm ci"),
	)

	ginkgo.It("mounts the observer read-only and exports NODE_OPTIONS before the legacy stage script", func(ctx ginkgo.SpecContext) {
		container := &jsObserverLegacyContainer{}
		stageBuilder := &jsObserverLegacyStageBuilder{container: container}

		attachJSObserver(stageBuilder, true, "/host/assets")
		gomega.Expect(userShell(ginkgo.GinkgoT().TempDir()).Install(ctx, nil, stageBuilder, true)).To(gomega.Succeed())

		gomega.Expect(container.serviceCommands).To(gomega.Equal([]string{jsObserverNodeOptionsExport(jsObserverContainerDir), "/.werf/shell/script.sh"}))
		gomega.Expect(container.volumes).To(gomega.ContainElement("/host/assets:/.werf/js-observer:ro"))
	})

	ginkgo.It("prepares an observer directory every container user can read", func(ctx ginkgo.SpecContext) {
		dir, err := prepareJSObserverAssets(ctx, filepath.Join(ginkgo.GinkgoT().TempDir(), "conveyor"))
		gomega.Expect(err).To(gomega.Succeed())

		info, err := os.Stat(dir)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(info.Mode().Perm()).To(gomega.Equal(os.FileMode(0o755)))
		gomega.Expect(filepath.Join(dir, jsobserver.BootstrapFileName)).To(gomega.BeAnExistingFile())
	})

	ginkgo.DescribeTable("extends NODE_OPTIONS of the environment and leaves later user settings in force",
		func(ctx context.Context, inherited, userCommand, expectedSuffix string, observed bool) {
			if _, err := exec.LookPath("node"); err != nil {
				ginkgo.Skip("node is not installed")
			}
			assetsDir, err := prepareJSObserverAssets(ctx, ginkgo.GinkgoT().TempDir())
			gomega.Expect(err).To(gomega.Succeed())

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
			gomega.Expect(err).To(gomega.Succeed(), string(output))

			bootstrap := "--require " + filepath.Join(assetsDir, jsobserver.BootstrapFileName)
			expected := strings.TrimSpace(strings.Join([]string{bootstrap, expectedSuffix}, " "))
			if !observed {
				expected = expectedSuffix
			}
			gomega.Expect(strings.TrimSpace(string(output))).To(gomega.Equal(fmt.Sprintf("%t %s", observed, expected)))
		},
		ginkgo.Entry("no NODE_OPTIONS in the base image", "", ":", "", true),
		ginkgo.Entry("NODE_OPTIONS of the base image", "--max-old-space-size=128", ":", "--max-old-space-size=128", true),
		ginkgo.Entry("NODE_OPTIONS extended by the user", "--max-old-space-size=128", `export NODE_OPTIONS="$NODE_OPTIONS --no-warnings"`, "--max-old-space-size=128 --no-warnings", true),
		ginkgo.Entry("NODE_OPTIONS replaced by the user", "--max-old-space-size=128", `export NODE_OPTIONS="--no-warnings"`, "--no-warnings", false),
	)
})
