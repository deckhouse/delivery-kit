package jsobserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var (
	rollupMainPackages  = []Package{{Name: "@scope/dep-b", Version: "2.0.0"}, {Name: "dep-a", Version: "1.2.3"}}
	rollupLazyPackages  = []Package{{Name: "linked-dep", Version: "3.0.0"}}
	esbuildAppPackages  = []Package{{Name: "dep-a", Version: "1.2.3"}, {Name: "linked-dep", Version: "3.0.0"}}
	esbuildChunkPackage = []Package{{Name: "@scope/dep-b", Version: "2.0.0"}}
)

var allEsbuildCommonJSOutputs = append(append(append(append(
	esbuildOutputs("dist/esbuild-disk"),
	expectedOutput{Path: "dist/esbuild-memory/app.js", MemoryCode: "/* app */", Packages: esbuildAppPackages},
	expectedOutput{Path: "dist/esbuild-memory/chunk.js", MemoryCode: "/* chunk */", Packages: esbuildChunkPackage}),
	esbuildOutputs("dist/esbuild-requested")...),
	esbuildOutputs("dist/esbuild-default")...),
	esbuildOutputs("dist/esbuild-context")...)

var rollupCommonJSOutputs = []expectedOutput{
	{Path: "dist/rollup-cjs/main.js", Packages: rollupMainPackages},
	{Path: "dist/rollup-cjs/lazy.js", Packages: rollupLazyPackages},
}

var _ = ginkgo.Describe("JavaScript observer assets", func() {
	ginkgo.DescribeTable("record per-output package owners without changing the build",
		func(ctx context.Context, script string, expected []expectedOutput) {
			expectObservedBuild(ctx, script, noPreparation, expected)
		},
		ginkgo.Entry("Rollup ES module API, generate and write", "build-rollup.mjs", []expectedOutput{
			{Path: "dist/rollup-generated/main.js", MemoryCode: "/* main */", Packages: rollupMainPackages},
			{Path: "dist/rollup-generated/lazy.js", MemoryCode: "/* lazy */", Packages: rollupLazyPackages},
			{Path: "dist/rollup-esm/main.js", Packages: rollupMainPackages},
			{Path: "dist/rollup-esm/lazy.js", Packages: rollupLazyPackages},
		}),
		ginkgo.Entry("Rollup CommonJS API writing to output.file", "build-rollup.cjs", rollupCommonJSOutputs),
		ginkgo.Entry("esbuild CommonJS API: build, write:false, requested metafile, default export, context", "build-esbuild.cjs", allEsbuildCommonJSOutputs),
		ginkgo.Entry("esbuild imported from an ES module", "build-esbuild.mjs", append(
			esbuildOutputs("dist/esbuild-esm-named"),
			esbuildOutputs("dist/esbuild-esm-default")...)),
	)

	ginkgo.DescribeTable("accepts bundler sources an earlier module hook returns as a Uint8Array",
		func(ctx context.Context, script string, expected []expectedOutput) {
			expectObservedBuild(ctx, script, func(fixture observerFixture) string {
				return "--require " + filepath.Join(fixture.ProjectDir, "prior-hook.cjs")
			}, expected)
		},
		ginkgo.Entry("Rollup", "build-rollup.cjs", rollupCommonJSOutputs),
		ginkgo.Entry("esbuild", "build-esbuild.cjs", allEsbuildCommonJSOutputs),
	)

	ginkgo.DescribeTable("leaves bundlers it does not support untouched and warns",
		func(ctx context.Context, script string, prepare func(observerFixture), warning string) {
			observed := expectObservedBuild(ctx, script, func(fixture observerFixture) string {
				prepare(fixture)
				return ""
			}, nil)

			events := readEvents(observed.LogPath)
			gomega.Expect(events).To(gomega.HaveLen(1))
			gomega.Expect(events[0].Warning).To(gomega.ContainSubstring(warning))
		},
		ginkgo.Entry("Rollup outside the supported major version", "build-rollup.cjs", func(fixture observerFixture) {
			fixture.setPackageVersion("rollup", "3.29.4")
		}, "Rollup 3.29.4 is not supported"),
		ginkgo.Entry("esbuild outside the supported minor version", "build-esbuild-plain.cjs", func(fixture observerFixture) {
			fixture.setPackageVersion("esbuild", "0.8.57")
		}, "esbuild 0.8.57 is not supported"),
		ginkgo.Entry("esbuild exports in an unexpected shape", "build-esbuild-plain.cjs", func(fixture observerFixture) {
			data, err := os.ReadFile("testdata/variants/esbuild-inherited-build.js")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(os.WriteFile(filepath.Join(fixture.ProjectDir, "node_modules", "esbuild", "lib", "main.js"), data, 0o644)).To(gomega.Succeed())
		}, "esbuild exports are not recognized"),
	)

	ginkgo.It("records only installed dependencies when the project root is unknown", func(ctx context.Context) {
		expectObservedBuild(ctx, "build-rollup.cjs", func(fixture observerFixture) string {
			for _, manifest := range []string{filepath.Join(fixture.Dir, "package.json"), filepath.Join(fixture.ProjectDir, "package.json")} {
				gomega.Expect(os.Remove(manifest)).To(gomega.Succeed())
			}
			for dir := fixture.Dir; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
				gomega.Expect(filepath.Join(dir, "package.json")).NotTo(gomega.BeAnExistingFile())
			}
			return ""
		}, []expectedOutput{{Path: "dist/rollup-cjs/main.js", Packages: rollupMainPackages}})
	})

	ginkgo.Describe("bounding event lines", func() {
		var main, lazy Output
		var fixture observerFixture

		ginkgo.BeforeEach(func(ctx context.Context) {
			fixture = newObserverFixture(ctx)
			runNode(ctx, fixture.ProjectDir, fixture.bootstrapOption(), "build-rollup.cjs")
			outputs := outputsByPath(readEvents(fixture.LogPath))
			main = outputs[filepath.Join(fixture.ProjectDir, "dist/rollup-cjs/main.js")]
			lazy = outputs[filepath.Join(fixture.ProjectDir, "dist/rollup-cjs/lazy.js")]
			gomega.Expect(eventLineBytes(main)).To(gomega.BeNumerically(">", eventLineBytes(lazy)))
			gomega.Expect(os.Remove(fixture.LogPath)).To(gomega.Succeed())
		})

		observe := func(ctx context.Context, maxEventBytes int) []Event {
			fixture.setMaxEventBytes(maxEventBytes)
			runNode(ctx, fixture.ProjectDir, fixture.bootstrapOption(), "build-rollup.cjs")
			data, err := os.ReadFile(fixture.LogPath)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			for _, line := range strings.SplitAfter(string(data), "\n") {
				gomega.Expect(len(line)).To(gomega.BeNumerically("<=", maxEventBytes))
			}
			return readEvents(fixture.LogPath)
		}

		ginkgo.It("keeps outputs that fit together in one line", func(ctx context.Context) {
			gomega.Expect(observe(ctx, eventLineBytes(main, lazy))).To(gomega.Equal([]Event{{Version: ProtocolVersion, Outputs: []Output{main, lazy}}}))
		})

		ginkgo.It("splits outputs that do not fit together", func(ctx context.Context) {
			gomega.Expect(observe(ctx, eventLineBytes(main, lazy)-1)).To(gomega.Equal([]Event{
				{Version: ProtocolVersion, Outputs: []Output{main}},
				{Version: ProtocolVersion, Outputs: []Output{lazy}},
			}))
		})

		ginkgo.It("replaces an output larger than a line with a warning", func(ctx context.Context) {
			events := observe(ctx, eventLineBytes(main)-1)
			gomega.Expect(events).To(gomega.HaveLen(2))
			gomega.Expect(events[0].Outputs).To(gomega.BeEmpty())
			gomega.Expect(events[0].Warning).To(gomega.ContainSubstring(main.Path))
			gomega.Expect(events[1]).To(gomega.Equal(Event{Version: ProtocolVersion, Outputs: []Output{lazy}}))
		})
	})

	ginkgo.It("warns instead of observing on Node.js without module.registerHooks", func(ctx context.Context) {
		baseline := newObserverFixture(ctx)
		baselineStdout, _ := runNode(ctx, baseline.ProjectDir, "", "build-rollup.mjs")

		observed := newObserverFixture(ctx)
		simulateOldNode := "--require " + filepath.Join(observed.ProjectDir, "no-register-hooks.cjs")
		observedStdout, _ := runNode(ctx, observed.ProjectDir, simulateOldNode+" "+observed.bootstrapOption(), "build-rollup.mjs")

		gomega.Expect(observedStdout).To(gomega.Equal(baselineStdout))
		events := readEvents(observed.LogPath)
		gomega.Expect(events).To(gomega.HaveLen(1))
		gomega.Expect(events[0].Outputs).To(gomega.BeEmpty())
		gomega.Expect(events[0].Warning).To(gomega.ContainSubstring("module.registerHooks"))
	})

	ginkgo.It("appends to observations recorded by earlier processes", func(ctx context.Context) {
		fixture := newObserverFixture(ctx)
		earlier := `{"version":1,"warning":"earlier stage"}` + "\n"
		gomega.Expect(os.Mkdir(filepath.Dir(fixture.LogPath), 0o700)).To(gomega.Succeed())
		gomega.Expect(os.WriteFile(fixture.LogPath, []byte(earlier), 0o600)).To(gomega.Succeed())

		runNode(ctx, fixture.ProjectDir, fixture.bootstrapOption(), "build-rollup.cjs")
		runNode(ctx, fixture.ProjectDir, fixture.bootstrapOption(), "build-esbuild.mjs")

		events := readEvents(fixture.LogPath)
		gomega.Expect(events).To(gomega.HaveLen(4))
		gomega.Expect(events[0].Warning).To(gomega.Equal("earlier stage"))
	})

	ginkgo.DescribeTable("refuses a log location another user could redirect",
		func(ctx context.Context, prepare func(fixture observerFixture) string) {
			fixture := newObserverFixture(ctx)
			target := prepare(fixture)

			_, stderr := runNode(ctx, fixture.ProjectDir, fixture.bootstrapOption(), "build-rollup.cjs")

			gomega.Expect(stderr).To(gomega.ContainSubstring("JavaScript bundle observer cannot record evidence"))
			gomega.Expect(target).NotTo(gomega.BeAnExistingFile())
			gomega.Expect(filepath.Join(fixture.ProjectDir, "dist", "rollup-cjs", "main.js")).To(gomega.BeAnExistingFile())
		},
		ginkgo.Entry("directory writable by others", func(fixture observerFixture) string {
			dir := filepath.Dir(fixture.LogPath)
			gomega.Expect(os.Mkdir(dir, 0o700)).To(gomega.Succeed())
			gomega.Expect(os.Chmod(dir, 0o777)).To(gomega.Succeed())
			return fixture.LogPath
		}),
		ginkgo.Entry("directory replaced with a symlink", func(fixture observerFixture) string {
			redirected := filepath.Join(fixture.Dir, "redirected")
			gomega.Expect(os.Mkdir(redirected, 0o700)).To(gomega.Succeed())
			gomega.Expect(os.Symlink(redirected, filepath.Dir(fixture.LogPath))).To(gomega.Succeed())
			return filepath.Join(redirected, filepath.Base(fixture.LogPath))
		}),
		ginkgo.Entry("log file replaced with a symlink", func(fixture observerFixture) string {
			gomega.Expect(os.Mkdir(filepath.Dir(fixture.LogPath), 0o700)).To(gomega.Succeed())
			redirected := filepath.Join(fixture.Dir, "redirected.jsonl")
			gomega.Expect(os.Symlink(redirected, fixture.LogPath)).To(gomega.Succeed())
			return redirected
		}),
	)

	ginkgo.It("writes world-readable assets that point the observer at the protocol log", func(ctx context.Context) {
		dir := ginkgo.GinkgoT().TempDir()
		gomega.Expect(WriteAssets(ctx, dir)).To(gomega.Succeed())

		for _, name := range []string{BootstrapFileName, "observer.cjs", "settings.json"} {
			info, err := os.Stat(filepath.Join(dir, name))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(info.Mode().Perm()).To(gomega.Equal(os.FileMode(0o644)))
		}
		settings, err := os.ReadFile(filepath.Join(dir, "settings.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(settings).To(gomega.MatchJSON(`{"logPath":"/tmp/.werf-js-observer/events.jsonl","protocolVersion":1,"maxEventBytes":1048576}`))
	})

	ginkgo.It("stops when the context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dir := ginkgo.GinkgoT().TempDir()

		gomega.Expect(WriteAssets(ctx, dir)).To(gomega.MatchError(context.Canceled))
		gomega.Expect(os.ReadDir(dir)).To(gomega.BeEmpty())
	})

	ginkgo.It("changes InstrumentationVersion together with the embedded observer", func() {
		hash := sha256.New()
		gomega.Expect(fs.WalkDir(assets, "assets", func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := assets.ReadFile(path)
			if err != nil {
				return err
			}
			hash.Write([]byte(path + "\x00"))
			hash.Write(data)
			return nil
		})).To(gomega.Succeed())

		// Cached stages keep the observations of the observer that built them;
		// bump InstrumentationVersion and update both values when the assets change.
		gomega.Expect(strings.Join([]string{InstrumentationVersion, hex.EncodeToString(hash.Sum(nil))}, ":")).To(gomega.Equal("2:17a7297543f8fda1adb79b9989b61d0caa7fa9518d0d5955f4990a3b0e1e0f82"))
	})
})
