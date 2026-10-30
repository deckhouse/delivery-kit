package build

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
	"github.com/werf/werf/v3/pkg/logging"
)

// webpackStageSettings is what a stage states beside the opt-in: the one configuration
// the collector attaches to, the proof that compilation writes and the cache the
// package manager installed from.
const webpackStageSettings = `"webpackSources":true,"webpackConfig":"/ui/webpack.config.js","webpackProof":"/private-build-metadata/ui.json","yarnCache":"/yarn/cache"`

const webpackStageEsbuild = `"esbuild":{"version":"0.25.0","loaderVersion":"4.3.0","entry":"/tools/esbuild/lib/main.js","binary":"/tools/esbuild/bin/esbuild","loader":"/ui/node_modules/esbuild-loader/dist/index.cjs","runtimeSource":"/tools/esbuild/internal/runtime/runtime.go"}`

// webpackDeclaration is the producer intent of a stage that runs a checked Webpack
// build, written on top of the ordinary one.
func webpackDeclaration(settings string) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(producerDeclaration()).To(gomega.ContainSubstring(`"subject":0`))

	return strings.Replace(producerDeclaration(), `"subject":0`, `"subject":0,`+settings, 1)
}

// stubWebpackCollector hands the phase a collector tree of its own. The collector a
// werf really carries is only linked into a build tagged to embed it; what it unpacks
// is proven where it is unpacked, in the collector package's own extraction spec.
func stubWebpackCollector(digest string) {
	ginkgo.GinkgoHelper()
	original := extractWebpackCollector
	extractWebpackCollector = func(directory string) (string, error) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return "", err
		}

		return digest, os.WriteFile(filepath.Join(directory, "activate.cjs"), []byte("// collector\n"), 0o644)
	}
	ginkgo.DeferCleanup(func() { extractWebpackCollector = original })
}

var _ = ginkgo.Describe("declaring a checked Webpack stage", func() {
	settings := func(fields ...string) string {
		return webpackDeclaration(strings.Join(fields, ","))
	}

	ginkgo.It("carries the paths the collector is run with", func() {
		parsed, err := parseSBOMBuildContextDeclaration([]byte(settings(webpackStageSettings, webpackStageEsbuild)))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		declared := parsed.Stages[stage.Install]
		gomega.Expect(declared.WebpackSources).To(gomega.BeTrue())
		gomega.Expect(declared.WebpackConfig).To(gomega.Equal("/ui/webpack.config.js"))
		gomega.Expect(declared.WebpackProof).To(gomega.Equal("/private-build-metadata/ui.json"))
		gomega.Expect(declared.YarnCache).To(gomega.Equal("/yarn/cache"))
		gomega.Expect(declared.Esbuild).To(gomega.Equal(&sbomBuildContextEsbuild{
			Version: "0.25.0", LoaderVersion: "4.3.0",
			Entry: "/tools/esbuild/lib/main.js", Binary: "/tools/esbuild/bin/esbuild",
			Loader: "/ui/node_modules/esbuild-loader/dist/index.cjs", RuntimeSource: "/tools/esbuild/internal/runtime/runtime.go",
		}))
	})

	ginkgo.DescribeTable("refuses a stage the collector could not be run for", func(declaration, expected string) {
		_, err := parseSBOMBuildContextDeclaration([]byte(declaration))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("no configuration to attach to",
			settings(strings.Replace(webpackStageSettings, `"webpackConfig":"/ui/webpack.config.js",`, "", 1)), "webpackConfig is required"),
		ginkgo.Entry("no proof to write",
			settings(strings.Replace(webpackStageSettings, `"webpackProof":"/private-build-metadata/ui.json",`, "", 1)), "webpackProof is required"),
		ginkgo.Entry("no cache to resolve installs from",
			settings(strings.Replace(webpackStageSettings, `,"yarnCache":"/yarn/cache"`, "", 1)), "yarnCache is required"),
		ginkgo.Entry("a configuration named relative to nothing",
			settings(strings.Replace(webpackStageSettings, `"/ui/webpack.config.js"`, `"ui/webpack.config.js"`, 1)), "webpackConfig must be a clean absolute path"),
		ginkgo.Entry("an uncleaned cache path",
			settings(strings.Replace(webpackStageSettings, `"/yarn/cache"`, `"/yarn/../yarn/cache"`, 1)), "yarnCache must be a clean absolute path"),
		// Nothing under werf's own mounts is in the image the proof is read from.
		ginkgo.Entry("a proof written into werf's scratch",
			settings(strings.Replace(webpackStageSettings, `"/private-build-metadata/ui.json"`, `"`+producerContextMount+`/ui.json"`, 1)),
			"is written to werf's own mount"),
		ginkgo.Entry("a proof written where the collector itself is mounted",
			settings(strings.Replace(webpackStageSettings, `"/private-build-metadata/ui.json"`, `"`+webpackCollectorMount+`/ui.json"`, 1)),
			"is written to werf's own mount"),
		ginkgo.Entry("paths without the opt-in",
			settings(strings.Replace(webpackStageSettings, `"webpackSources":true,`, "", 1)), "webpackConfig requires webpackSources"),
		ginkgo.Entry("an esbuild without the opt-in",
			settings(webpackStageEsbuild), "esbuild requires webpackSources"),
		ginkgo.Entry("an esbuild that is no object",
			settings(webpackStageSettings, `"esbuild":null`), "esbuild must be an object"),
		ginkgo.Entry("an unknown esbuild member",
			settings(webpackStageSettings, strings.Replace(webpackStageEsbuild, `"version"`, `"extra":true,"version"`, 1)), "unknown field"),
	)

	// The four files and the version pair are one declaration: a stage naming some of
	// them has stated something nobody can act on.
	ginkgo.DescribeTable("refuses an esbuild named in part", func(member, expected string) {
		_, err := parseSBOMBuildContextDeclaration([]byte(settings(webpackStageSettings, strings.Replace(webpackStageEsbuild, member, "", 1))))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("version", `"version":"0.25.0",`, "esbuild.version is required"),
		ginkgo.Entry("loaderVersion", `"loaderVersion":"4.3.0",`, "esbuild.loaderVersion is required"),
		ginkgo.Entry("entry", `"entry":"/tools/esbuild/lib/main.js",`, "esbuild.entry is required"),
		ginkgo.Entry("binary", `"binary":"/tools/esbuild/bin/esbuild",`, "esbuild.binary is required"),
		ginkgo.Entry("loader", `"loader":"/ui/node_modules/esbuild-loader/dist/index.cjs",`, "esbuild.loader is required"),
		ginkgo.Entry("runtimeSource", `,"runtimeSource":"/tools/esbuild/internal/runtime/runtime.go"`, "esbuild.runtimeSource is required"),
	)

	ginkgo.It("refuses an esbuild file named relative to nothing", func() {
		declaration := settings(webpackStageSettings, strings.Replace(webpackStageEsbuild, `"/tools/esbuild/bin/esbuild"`, `"esbuild"`, 1))
		_, err := parseSBOMBuildContextDeclaration([]byte(declaration))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("esbuild.binary must be a clean absolute path")))
	})
})

var _ = ginkgo.Describe("delivering the webpack collector into the stage", func() {
	deliver := func(ctx context.Context, fixture *producerFixture) *sbomProducerContext {
		ginkgo.GinkgoHelper()
		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(input).NotTo(gomega.BeNil())
		fixture.phase.producerInput = input
		ginkgo.DeferCleanup(func() { gomega.Expect(input.remove()).To(gomega.Succeed()) })

		return input
	}

	ginkgo.It("mounts the collector read-only and names it in the build environment", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: webpackDeclaration(webpackStageSettings + "," + webpackStageEsbuild)})
		input := deliver(ctx, fixture)
		gomega.Expect(input.webpack).NotTo(gomega.BeNil())
		gomega.Expect(input.webpack.directory).To(gomega.HavePrefix(fixture.phase.Conveyor.tmpDir),
			"the collector is unpacked into the conveyor's own temp directory")
		gomega.Expect(filepath.Join(input.webpack.directory, "activate.cjs")).To(gomega.BeAnExistingFile())

		stageImage := stage.NewStageImage(fixture.phase.Conveyor.ContainerBackend, "base", container_backend.NewLegacyStageImage(nil, "stage", fixture.phase.Conveyor.ContainerBackend, producerPlatform))
		fixture.stg.SetStageImage(stageImage)
		gomega.Expect(fixture.phase.prepareStageInstructions(ctx, fixture.img, fixture.stg)).To(gomega.Succeed())
		builder, ok := stageImage.Builder.StapelStageBuilder().(*stage_builder.StapelStageBuilder)
		gomega.Expect(ok).To(gomega.BeTrue())

		gomega.Expect(builder.BuildVolumes).To(gomega.ContainElement(input.webpack.directory+":"+webpackCollectorMount+":ro"),
			"the stage reads the collector, and only reads it")
		gomega.Expect(builder.BuildVolumes).To(gomega.ContainElement(input.directory+":"+producerContextMount+":ro"),
			"the context the collector reads its verified originals from is mounted beside it")
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("NODE_OPTIONS", "--require "+webpackCollectorMount+"/activate.cjs"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_WEBPACK_CONFIG", "/ui/webpack.config.js"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_WEBPACK_PROOF", "/private-build-metadata/ui.json"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_YARN_CACHE", "/yarn/cache"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_ESBUILD_VERSION", "0.25.0"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_ESBUILD_LOADER_VERSION", "4.3.0"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_ESBUILD_ENTRY", "/tools/esbuild/lib/main.js"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_ESBUILD_BINARY", "/tools/esbuild/bin/esbuild"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_ESBUILD_LOADER", "/ui/node_modules/esbuild-loader/dist/index.cjs"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("DK_SBOM_ESBUILD_RUNTIME_SOURCE", "/tools/esbuild/internal/runtime/runtime.go"))
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("ESBUILD_BINARY_PATH", "/tools/esbuild/bin/esbuild"),
			"the esbuild client runs the executable the declaration names")
		gomega.Expect(builder.BuildTimeEnvs).To(gomega.HaveKeyWithValue("SBOM_BUILD_CONTEXT", input.path))
	})

	ginkgo.It("hands a stage that declared no Webpack build no collector at all", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{})
		input := deliver(ctx, fixture)
		gomega.Expect(input.webpack).To(gomega.BeNil())

		stageImage := stage.NewStageImage(fixture.phase.Conveyor.ContainerBackend, "base", container_backend.NewLegacyStageImage(nil, "stage", fixture.phase.Conveyor.ContainerBackend, producerPlatform))
		fixture.stg.SetStageImage(stageImage)
		gomega.Expect(fixture.phase.prepareStageInstructions(ctx, fixture.img, fixture.stg)).To(gomega.Succeed())
		builder, ok := stageImage.Builder.StapelStageBuilder().(*stage_builder.StapelStageBuilder)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(builder.BuildVolumes).To(gomega.HaveLen(1))
		gomega.Expect(builder.BuildTimeEnvs).NotTo(gomega.HaveKey("NODE_OPTIONS"))
	})

	ginkgo.It("refuses the stage when the collector cannot be delivered", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		original := extractWebpackCollector
		extractWebpackCollector = func(string) (string, error) {
			return "", fmt.Errorf("no-data: this werf carries no SBOM webpack collector")
		}
		ginkgo.DeferCleanup(func() { extractWebpackCollector = original })

		fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: webpackDeclaration(webpackStageSettings)})
		_, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("webpack collector: no-data: this werf carries no SBOM webpack collector")))

		left, err := os.ReadDir(fixture.phase.Conveyor.tmpDir)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty(), "a refused stage strands no scratch of the context it was being built against")
	})

	ginkgo.It("releases the collector of a context it drops", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		stubWebpackCollector("collector-digest")
		fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: webpackDeclaration(webpackStageSettings)})
		input, err := fixture.phase.producerContext(ctx, fixture.img, fixture.stg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(input.remove()).To(gomega.Succeed())
		gomega.Expect(input.webpack.directory).NotTo(gomega.BeADirectory())
		gomega.Expect(input.directory).NotTo(gomega.BeADirectory())
	})

	ginkgo.Describe("the stage it selects", func() {
		ginkgo.It("is another stage for another collector, another path and another esbuild", func(specCtx ginkgo.SpecContext) {
			ctx := logging.WithLogger(specCtx)
			fixture := newProducerFixture(ctx, producerFixtureOptions{declaration: webpackDeclaration(webpackStageSettings)})
			// One build, one prepared source, one recipe: what differs between these
			// stages is only what the collector is and what it is run with.
			checksum := func(declaration, digest string) string {
				ginkgo.GinkgoHelper()
				stubWebpackCollector(digest)
				fixture.img.StapelImageConfig.ImageBaseConfig().ImageSpec.Labels[sbomBuildContextLabel] = declaration

				return deliver(ctx, fixture).checksum
			}

			declared := checksum(webpackDeclaration(webpackStageSettings), "collector-digest")
			gomega.Expect(checksum(webpackDeclaration(webpackStageSettings), "collector-digest")).To(gomega.Equal(declared),
				"the same collector and the same declaration build the same stage")
			gomega.Expect(checksum(webpackDeclaration(webpackStageSettings), "another-collector")).NotTo(gomega.Equal(declared),
				"a werf carrying another collector instruments the build differently")
			gomega.Expect(checksum(webpackDeclaration(strings.Replace(webpackStageSettings, `"/yarn/cache"`, `"/other/cache"`, 1)), "collector-digest")).NotTo(gomega.Equal(declared),
				"a build resolving its installs from another cache is another build")
			gomega.Expect(checksum(webpackDeclaration(webpackStageSettings+","+webpackStageEsbuild), "collector-digest")).NotTo(gomega.Equal(declared),
				"a build transformed by the instrumented esbuild is another build")
		})
	})

	ginkgo.Describe("the environment it is run with", func() {
		collector := func(settings, imageEnv string) map[string]string {
			ginkgo.GinkgoHelper()
			stubWebpackCollector("collector-digest")
			parsed, err := parseSBOMBuildContextDeclaration([]byte(webpackDeclaration(settings)))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			phase := newTestBuildPhase(nil, nil)
			phase.Conveyor.tmpDir = ginkgo.GinkgoT().TempDir()
			var env []string
			if imageEnv != "" {
				env = []string{"PATH=/usr/bin", imageEnv, "LANG=C"}
			}
			delivered, digest, err := phase.webpackCollector(parsed.Stages[stage.Install], env)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(digest).To(gomega.Equal("collector-digest"))
			ginkgo.DeferCleanup(func() { gomega.Expect(os.RemoveAll(delivered.directory)).To(gomega.Succeed()) })

			return delivered.env
		}

		ginkgo.It("keeps the node options the preceding image states", func() {
			gomega.Expect(collector(webpackStageSettings, "NODE_OPTIONS=--max-old-space-size=8192")).To(
				gomega.HaveKeyWithValue("NODE_OPTIONS", "--max-old-space-size=8192 --require "+webpackCollectorMount+"/activate.cjs"))
		})

		ginkgo.It("states only its own when the image states none", func() {
			gomega.Expect(collector(webpackStageSettings, "")).To(
				gomega.HaveKeyWithValue("NODE_OPTIONS", "--require "+webpackCollectorMount+"/activate.cjs"))
		})

		ginkgo.It("names no esbuild a stage did not declare", func() {
			env := collector(webpackStageSettings, "")
			for name := range env {
				gomega.Expect(name).NotTo(gomega.HavePrefix("DK_SBOM_ESBUILD_"))
			}
			gomega.Expect(env).NotTo(gomega.HaveKey("ESBUILD_BINARY_PATH"))
		})
	})
})

var _ = ginkgo.Describe("reading one variable of an image config", func() {
	ginkgo.It("is the value its containers are given", func() {
		gomega.Expect(imageEnvironmentValue([]string{"PATH=/bin", "NODE_OPTIONS=--first", "NODE_OPTIONS=--second"}, "NODE_OPTIONS")).
			To(gomega.Equal("--second"), "a config repeating a variable keeps the last")
		gomega.Expect(imageEnvironmentValue([]string{"NODE_OPTIONS_EXTRA=--first"}, "NODE_OPTIONS")).To(gomega.BeEmpty())
		gomega.Expect(imageEnvironmentValue(nil, "NODE_OPTIONS")).To(gomega.BeEmpty())
	})
})

// The producer intent of a declared image is what the phase hashes the stage against,
// so a new member of it has to be in the bytes that are hashed.
var _ = ginkgo.Describe("the encoded stage intent", func() {
	ginkgo.It("carries what the collector is run with", func() {
		parsed, err := parseSBOMBuildContextDeclaration([]byte(webpackDeclaration(webpackStageSettings + "," + webpackStageEsbuild)))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		encoded, err := json.Marshal(parsed.Stages[stage.Install])
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, member := range []string{`"webpackConfig":"/ui/webpack.config.js"`, `"webpackProof":"/private-build-metadata/ui.json"`, `"yarnCache":"/yarn/cache"`, `"binary":"/tools/esbuild/bin/esbuild"`} {
			gomega.Expect(string(encoded)).To(gomega.ContainSubstring(member))
		}
	})
})
