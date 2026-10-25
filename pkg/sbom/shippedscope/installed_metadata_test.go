package shippedscope

import (
	"bytes"
	"fmt"
	"maps"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/logboek"
)

var _ = Describe("InstalledPackageFiles", func() {
	It("selects installed metadata and licenses without collecting application payloads", func(ctx SpecContext) {
		python := "/opt/vendor/requests-2.32.3.dist-info/"
		node := "/app/node_modules/@scope/pkg/"
		lua := "/usr/lib/luarocks/rocks-5.4/say/1.4.1-3/"
		files := []string{
			python + "METADATA", python + "RECORD", python + "direct_url.json", python + "licenses/custom-terms.txt",
			"/opt/vendor/requests/__init__.py", "/app/.venv/pyvenv.cfg",
			node + "package.json", node + "LICENSE.md", node + "MIT-LICENSE", node + "index.js",
			node + "examples/package.json", "/app/package.json", "/app/node_modules/.package-lock.json",
			"/app/node_modules/.pnpm/pkg@2.0/node_modules/pkg/package.json",
			"/usr/share/nodejs/system/package.json",
			lua + "say-1.4.1-3.rockspec", lua + "rock_manifest", lua + "doc/sample.rockspec",
			"/app/sample.rockspec", "/usr/share/lua/5.4/say/init.lua",
		}
		index := &FileIndex{Files: make(map[string]File)}
		for _, name := range files {
			index.Files[name] = File{Size: 100}
		}

		selected := InstalledPackageFiles(ctx, index)
		Expect(slices.Sorted(maps.Keys(selected[EcosystemPython]))).To(ConsistOf(python+"METADATA", python+"RECORD", python+"direct_url.json", python+"licenses/custom-terms.txt", "/app/.venv/pyvenv.cfg"))
		Expect(slices.Sorted(maps.Keys(selected[EcosystemJavaScript]))).To(ConsistOf(node+"package.json", node+"LICENSE.md", node+"MIT-LICENSE", "/app/node_modules/.pnpm/pkg@2.0/node_modules/pkg/package.json", "/usr/share/nodejs/system/package.json"))
		Expect(slices.Sorted(maps.Keys(selected[EcosystemLua]))).To(Equal([]string{lua + "say-1.4.1-3.rockspec"}))
		Expect(InstalledPackageFiles(ctx, index)).To(Equal(selected))
	})

	It("keeps separate Python environments and installed eggs but excludes source egg metadata", func(ctx SpecContext) {
		index := &FileIndex{Files: map[string]File{
			"/a/.venv/lib/python3.12/site-packages/foo-1.dist-info/METADATA":      {},
			"/b/.venv/lib/python3.12/site-packages/foo-2.dist-info/METADATA":      {},
			"/usr/lib/python3/dist-packages/legacy.egg-info":                      {},
			"/usr/lib/python3/dist-packages/other.egg-info/PKG-INFO":              {},
			"/opt/vendor/installed.egg-info/PKG-INFO":                             {},
			"/opt/vendor/installed.egg-info/installed-files.txt":                  {},
			"/src/project.egg-info/PKG-INFO":                                      {},
			"/usr/lib/python3/site-packages/tool/tests/fixture.egg-info/PKG-INFO": {},
			"/usr/lib/python3/site-packages/tool/tests/standalone.egg-info":       {},
			"/src/project.egg-info/SOURCES.txt":                                   {},
			"/src/PKG-INFO":                                                       {},
			"/cache/package.whl":                                                  {},
		}}
		selected := InstalledPackageFiles(ctx, index)
		Expect(slices.Sorted(maps.Keys(selected[EcosystemPython]))).To(ConsistOf(
			"/a/.venv/lib/python3.12/site-packages/foo-1.dist-info/METADATA",
			"/b/.venv/lib/python3.12/site-packages/foo-2.dist-info/METADATA",
			"/usr/lib/python3/dist-packages/legacy.egg-info",
			"/usr/lib/python3/dist-packages/other.egg-info/PKG-INFO",
			"/opt/vendor/installed.egg-info/PKG-INFO",
			"/opt/vendor/installed.egg-info/installed-files.txt",
		))
	})

	It("uses surviving layer contents and ignores removed metadata", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("app/node_modules/gone/package.json", "old"), regularFile("opaque", "metadata")},
			[]tarEntry{whiteout("app/node_modules/gone/.wh.package.json"), hardlink("app/node_modules/kept/package.json", "opaque")},
		)
		Expect(err).NotTo(HaveOccurred())
		index, err := IndexImageFiles(ctx, img)
		Expect(err).NotTo(HaveOccurred())
		Expect(InstalledPackageFiles(ctx, index)[EcosystemJavaScript]).To(Equal(map[string]string{"/app/node_modules/kept/package.json": "/app/node_modules/kept/package.json"}))
	})

	It("resolves metadata file symlinks without treating dangling or looping links as files", func(ctx SpecContext) {
		index := &FileIndex{
			Files: map[string]File{"/shared/manifest": {Size: 123}},
			Symlinks: map[string]string{
				"/app/node_modules/pkg/package.json":     "../../../shared/alias",
				"/shared/alias":                          "manifest",
				"/app/node_modules/missing/package.json": "/absent",
				"/app/node_modules/loop/package.json":    "package.json",
			},
		}
		Expect(InstalledPackageFiles(ctx, index)[EcosystemJavaScript]).To(Equal(map[string]string{"/app/node_modules/pkg/package.json": "/shared/manifest"}))
	})

	It("projects linked installation directories without copying their code", func(ctx SpecContext) {
		index := &FileIndex{
			Files: map[string]File{
				"/vendor/pkg/package.json":          {Size: 123},
				"/vendor/pkg/LICENSE":               {Size: 100},
				"/vendor/pkg/index.js":              {Size: 200},
				"/vendor/pkg/examples/package.json": {Size: 50},
			},
			Symlinks: map[string]string{"/app/node_modules/pkg": "/vendor/pkg"},
		}
		Expect(InstalledPackageFiles(ctx, index)[EcosystemJavaScript]).To(Equal(map[string]string{"/app/node_modules/pkg/package.json": "/vendor/pkg/package.json", "/app/node_modules/pkg/LICENSE": "/vendor/pkg/LICENSE"}))
	})

	It("bounds additional reads by indexed sizes and warns instead of reading oversized metadata", func(specCtx SpecContext) {
		var output bytes.Buffer
		ctx := logboek.NewContext(specCtx, logboek.NewLogger(&output, &output))
		index := &FileIndex{Files: map[string]File{
			"/app/node_modules/oversized/package.json": {Size: maxInstalledMetadataFileBytes + 1},
		}}
		for i := 0; i < 20; i++ {
			index.Files[fmt.Sprintf("/app/node_modules/pkg%02d/package.json", i)] = File{Size: maxInstalledMetadataFileBytes}
		}
		selected := InstalledPackageFiles(ctx, index)
		Expect(slices.Sorted(maps.Keys(selected[EcosystemJavaScript]))).To(HaveLen(int(maxInstalledMetadataBytes / maxInstalledMetadataFileBytes)))
		Expect(slices.Sorted(maps.Keys(selected[EcosystemJavaScript]))).NotTo(ContainElement("/app/node_modules/oversized/package.json"))
		Expect(output.String()).To(ContainSubstring("installed package metadata"))
		Expect(slices.Sorted(maps.Keys(index.Files))).To(HaveLen(21), "selection must not mutate the shared file index")
	})
})
