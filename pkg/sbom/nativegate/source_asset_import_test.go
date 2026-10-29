package nativegate

import (
	"context"
	"os"
	"path/filepath"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// assetCase builds the snapshots of one import the way the build's backend builds them,
// on real directories.
type assetCase struct {
	source    []treeEntry
	target    []treeEntry
	scope     ImportScope
	afterCopy func(targetRoot string)
}

func (c assetCase) snapshots(ctx context.Context) (source, before, after *shippedscope.FileIndex) {
	sourceRoot, targetRoot := treeRoot(c.source), treeRoot(c.target)
	source, before = treeIndex(ctx, sourceRoot), treeIndex(ctx, targetRoot)
	runImport(ctx, sourceRoot, targetRoot, c.scope)
	if c.afterCopy != nil {
		c.afterCopy(targetRoot)
	}

	return source, before, treeIndex(ctx, targetRoot)
}

var _ = ginkgo.Describe("projecting asset imports", func() {
	ginkgo.It("places the asset root behind the destination links and maps the files the import carried", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{
				treeFile("opt/app/bin/tool", "tool-bytes"),
				treeFile("opt/app/assets/main.js", "js-bytes"),
				// Equal bytes this import does not carry confer nothing.
				treeFile("opt/other/thing", "tool-bytes"),
			},
			target: []treeEntry{treeDir("real/dest"), treeLink("dest", "real/dest")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		gomega.Expect(ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app")).To(gomega.Equal("/real/dest"))
		gomega.Expect(ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app/assets")).To(gomega.Equal("/real/dest/assets"))

		mapped, err := ProjectImportedFiles(ctx, source, before, after, c.scope, []string{
			"/opt/app/bin/tool",
			"/opt/app/assets/main.js",
			"/opt/app/bin/tool",
			"/opt/other/thing",
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(mapped).To(gomega.Equal(map[string]string{
			"/opt/app/bin/tool":       "/real/dest/bin/tool",
			"/opt/app/assets/main.js": "/real/dest/assets/main.js",
		}))
	})

	ginkgo.It("maps only what the import filters carried, though the target holds the same bytes where they did not write", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{
				treeFile("opt/app/keep/one.js", "one-bytes"),
				treeFile("opt/app/drop/two.js", "two-bytes"),
			},
			target: []treeEntry{treeFile("dest/drop/two.js", "two-bytes")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest", IncludePaths: []string{"keep"}},
		}
		source, before, after := c.snapshots(ctx)

		gomega.Expect(ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app")).To(gomega.Equal("/dest"))
		gomega.Expect(ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/opt/app/keep/one.js", "/opt/app/drop/two.js"})).To(gomega.Equal(map[string]string{
			"/opt/app/keep/one.js": "/dest/keep/one.js",
		}))
	})

	ginkgo.It("drops a file the stage removed or overwrote after the import", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{
				treeFile("opt/app/a.js", "a-bytes"),
				treeFile("opt/app/b.js", "b-bytes"),
				treeFile("opt/app/c.js", "c-bytes"),
			},
			scope: ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.Remove(filepath.Join(targetRoot, "dest/a.js"))).To(gomega.Succeed())
				gomega.Expect(os.WriteFile(filepath.Join(targetRoot, "dest/b.js"), []byte("other-bytes"), 0o644)).To(gomega.Succeed())
			},
		}
		source, before, after := c.snapshots(ctx)

		gomega.Expect(ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/opt/app/a.js", "/opt/app/b.js", "/opt/app/c.js"})).To(gomega.Equal(map[string]string{
			"/opt/app/c.js": "/dest/c.js",
		}))
	})

	ginkgo.It("places the asset root even when no file of it is carried or asked for", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/drop/two.js", "two-bytes")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest", ExcludePaths: []string{"drop"}},
		}
		source, before, after := c.snapshots(ctx)

		gomega.Expect(ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app")).To(gomega.Equal("/dest"))
		gomega.Expect(ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/opt/app/drop/two.js"})).To(gomega.BeEmpty())
		gomega.Expect(ProjectImportedFiles(ctx, source, before, after, c.scope, nil)).To(gomega.BeEmpty())
	})

	ginkgo.It("follows the symlinked directories on the way to the import source", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("real/app/assets/main.js", "js-bytes"), treeLink("opt", "real")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		gomega.Expect(ProjectImportedDirectory(ctx, source, before, after, c.scope, "/real/app/assets")).To(gomega.Equal("/dest/assets"))
		gomega.Expect(ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/real/app/assets/main.js"})).To(gomega.Equal(map[string]string{
			"/real/app/assets/main.js": "/dest/assets/main.js",
		}))
	})

	ginkgo.It("refuses a destination whose symlinks the stage changed under the import", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes")},
			target: []treeEntry{treeDir("real/dest"), treeLink("dest", "real/dest")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.Remove(filepath.Join(targetRoot, "dest"))).To(gomega.Succeed())
				gomega.Expect(os.Symlink("other/dest", filepath.Join(targetRoot, "dest"))).To(gomega.Succeed())
			},
		}
		source, before, after := c.snapshots(ctx)

		_, err := ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
		_, err = ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/opt/app/main.js"})
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses an asset root the import source does not hold", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes"), treeFile("opt/other/thing", "thing-bytes")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		_, err := ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/other")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
		_, err = ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app/main.js")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses an import source that is a file or a symlink rather than an asset directory", func(ctx ginkgo.SpecContext) {
		file := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes")},
			scope:  ImportScope{FromPath: "/opt/app/main.js", ToPath: "/dest/main.js"},
		}
		source, before, after := file.snapshots(ctx)

		_, err := ProjectImportedDirectory(ctx, source, before, after, file.scope, "/opt/app")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
		_, err = ProjectImportedFiles(ctx, source, before, after, file.scope, []string{"/opt/app/main.js"})
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))

		link := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes"), treeLink("opt/link", "app")},
			scope:  ImportScope{FromPath: "/opt/link", ToPath: "/dest"},
		}
		source, before, after = link.snapshots(ctx)

		_, err = ProjectImportedDirectory(ctx, source, before, after, link.scope, "/opt/app")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
		_, err = ProjectImportedFiles(ctx, source, before, after, link.scope, []string{"/opt/app/main.js"})
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses an unknown copy backend even when no file is asked for", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes")},
			scope:  ImportScope{Backend: "podman", FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		_, err := ProjectImportedDirectory(ctx, source, before, after, c.scope, "/opt/app")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
		_, err = ProjectImportedFiles(ctx, source, before, after, c.scope, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses asset paths that are not clean rooted paths of the source", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		for _, directory := range []string{"/opt/app/../app", "opt/app", "/opt/app/"} {
			_, err := ProjectImportedDirectory(ctx, source, before, after, c.scope, directory)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("clean rooted path")))
		}
	})

	ginkgo.It("refuses a file the source image does not hold instead of leaving it out", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes"), treeDir("opt/app/assets")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		_, err := ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/opt/app/absent.js"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("outside the indexed source")))
		_, err = ProjectImportedFiles(ctx, source, before, after, c.scope, []string{"/opt/app/assets"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("outside the indexed source")))
	})

	ginkgo.It("refuses incomplete snapshots instead of placing assets from part of them", func(ctx ginkgo.SpecContext) {
		c := assetCase{
			source: []treeEntry{treeFile("opt/app/main.js", "js-bytes")},
			scope:  ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		}
		source, before, after := c.snapshots(ctx)

		_, err := ProjectImportedDirectory(ctx, nil, before, after, c.scope, "/opt/app")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))

		incomplete := *after
		incomplete.Incomplete = true
		_, err = ProjectImportedFiles(ctx, source, before, &incomplete, c.scope, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))

		withoutDirectories := *before
		withoutDirectories.Directories = nil
		_, err = ProjectImportedDirectory(ctx, source, &withoutDirectories, after, c.scope, "/opt/app")
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})
})
