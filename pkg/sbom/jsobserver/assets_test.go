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

type expectedOutput struct {
	Path string
	// MemoryCode is set for outputs kept in memory, whose digest covers the
	// code the bundler returned rather than a file on disk.
	MemoryCode string
	Packages   []Package
}

var (
	rollupMainPackages  = []Package{{Name: "@scope/dep-b", Version: "2.0.0"}, {Name: "dep-a", Version: "1.2.3"}}
	rollupLazyPackages  = []Package{{Name: "linked-dep", Version: "3.0.0"}}
	esbuildAppPackages  = []Package{{Name: "dep-a", Version: "1.2.3"}, {Name: "linked-dep", Version: "3.0.0"}}
	esbuildChunkPackage = []Package{{Name: "@scope/dep-b", Version: "2.0.0"}}
)

func esbuildOutputs(dir string) []expectedOutput {
	return []expectedOutput{
		{Path: dir + "/app.js", Packages: esbuildAppPackages},
		{Path: dir + "/chunk.js", Packages: esbuildChunkPackage},
	}
}

var _ = ginkgo.Describe("JavaScript observer assets", func() {
	ginkgo.DescribeTable("record per-output package owners without changing the build",
		func(ctx context.Context, script string, expected []expectedOutput) {
			baseline := newObserverFixture(ctx)
			baselineStdout, _ := runNode(ctx, baseline.ProjectDir, "", script)

			observed := newObserverFixture(ctx)
			observedStdout, _ := runNode(ctx, observed.ProjectDir, observed.bootstrapOption(), script)

			gomega.Expect(observedStdout).To(gomega.Equal(baselineStdout))
			gomega.Expect(treeContents(filepath.Join(observed.ProjectDir, "dist"))).To(gomega.Equal(treeContents(filepath.Join(baseline.ProjectDir, "dist"))))

			outputs := outputsByPath(readEvents(observed.LogPath))
			var expectedPaths []string
			for _, want := range expected {
				path := filepath.Join(observed.ProjectDir, want.Path)
				expectedPaths = append(expectedPaths, path)
				digest := digestOf([]byte(want.MemoryCode))
				if want.MemoryCode == "" {
					data, err := os.ReadFile(path)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					digest = digestOf(data)
				}
				gomega.Expect(outputs).To(gomega.HaveKeyWithValue(path, Output{Path: path, Digest: digest, Packages: want.Packages}))
			}
			gomega.Expect(sortedKeys(outputs)).To(gomega.ConsistOf(expectedPaths))
		},
		ginkgo.Entry("Rollup ES module API, generate and write", "build-rollup.mjs", []expectedOutput{
			{Path: "dist/rollup-generated/main.js", MemoryCode: "/* main */", Packages: rollupMainPackages},
			{Path: "dist/rollup-generated/lazy.js", MemoryCode: "/* lazy */", Packages: rollupLazyPackages},
			{Path: "dist/rollup-esm/main.js", Packages: rollupMainPackages},
			{Path: "dist/rollup-esm/lazy.js", Packages: rollupLazyPackages},
		}),
		ginkgo.Entry("Rollup CommonJS API writing to output.file", "build-rollup.cjs", []expectedOutput{
			{Path: "dist/rollup-cjs/main.js", Packages: rollupMainPackages},
			{Path: "dist/rollup-cjs/lazy.js", Packages: rollupLazyPackages},
		}),
		ginkgo.Entry("esbuild CommonJS API: build, write:false, requested metafile, default export, context", "build-esbuild.cjs", append(append(append(append(
			esbuildOutputs("dist/esbuild-disk"),
			expectedOutput{Path: "dist/esbuild-memory/app.js", MemoryCode: "/* app */", Packages: esbuildAppPackages},
			expectedOutput{Path: "dist/esbuild-memory/chunk.js", MemoryCode: "/* chunk */", Packages: esbuildChunkPackage}),
			esbuildOutputs("dist/esbuild-requested")...),
			esbuildOutputs("dist/esbuild-default")...),
			esbuildOutputs("dist/esbuild-context")...)),
		ginkgo.Entry("esbuild imported from an ES module", "build-esbuild.mjs", append(
			esbuildOutputs("dist/esbuild-esm-named"),
			esbuildOutputs("dist/esbuild-esm-default")...)),
	)

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
		gomega.Expect(strings.Join([]string{InstrumentationVersion, hex.EncodeToString(hash.Sum(nil))}, ":")).To(gomega.Equal("1:8100f07f690b5694c48da8c3e342270b0dd1f076e04da5aacb9d1715f7a4f526"))
	})
})
