package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
	copyrec "github.com/werf/copy-recurse"
	"github.com/werf/werf/v3/pkg/path_matcher"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type treeEntry struct {
	path string
	body string
	link string
}

func treeFile(path, body string) treeEntry { return treeEntry{path: path, body: body} }

func treeDir(path string) treeEntry { return treeEntry{path: path} }

func treeLink(path, target string) treeEntry { return treeEntry{path: path, link: target} }

func writeTree(root string, entries []treeEntry) {
	for _, entry := range entries {
		full := filepath.Join(root, entry.path)
		switch {
		case entry.link != "":
			gomega.Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(gomega.Succeed())
			gomega.Expect(os.Symlink(entry.link, full)).To(gomega.Succeed())
		case entry.body != "":
			gomega.Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(gomega.Succeed())
			gomega.Expect(os.WriteFile(full, []byte(entry.body), 0o644)).To(gomega.Succeed())
		default:
			gomega.Expect(os.MkdirAll(full, 0o755)).To(gomega.Succeed())
		}
	}
}

func treeRoot(entries []treeEntry) string {
	root, err := filepath.EvalSymlinks(ginkgo.GinkgoT().TempDir())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	writeTree(root, entries)

	return root
}

// treeIndex indexes a real directory the way an image is indexed, by handing its contents
// to the production indexer as a layer.
func treeIndex(ctx context.Context, root string) *shippedscope.FileIndex {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	gomega.Expect(filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(name); err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		header.Name = relative
		if info.IsDir() {
			header.Name += "/"
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		body, err := os.Open(name)
		if err != nil {
			return err
		}
		defer body.Close()

		_, err = io.Copy(writer, body)

		return err
	})).To(gomega.Succeed())
	gomega.Expect(writer.Close()).To(gomega.Succeed())

	layer, err := tarball.LayerFromReader(&buffer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	index, err := shippedscope.IndexImageFiles(ctx, image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return index
}

// runImport performs the import the way the build's backend performs it, on real
// directories.
func runImport(ctx context.Context, sourceRoot, targetRoot string, scope ImportScope) {
	if scope.Backend == ImportBackendRsync {
		runRsyncImport(ctx, sourceRoot, targetRoot, scope)

		return
	}

	runCopyRecurseImport(ctx, sourceRoot, targetRoot, scope)
}

// runCopyRecurseImport performs the import the way the buildah backend does.
func runCopyRecurseImport(ctx context.Context, sourceRoot, targetRoot string, scope ImportScope) {
	from := filepath.Clean(scope.FromPath)
	fromParent, err := securejoin.SecureJoin(sourceRoot, filepath.Dir(from))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	absFrom := filepath.Join(fromParent, filepath.Base(from))

	absTo, err := securejoin.SecureJoin(targetRoot, scope.ToPath)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	absTo = normalizedImportDestination(absFrom, absTo)

	matcher := path_matcher.NewPathMatcher(path_matcher.PathMatcherOptions{
		IncludeGlobs: scope.IncludePaths,
		ExcludeGlobs: scope.ExcludePaths,
	})
	copier, err := copyrec.New(absFrom, absTo, copyrec.Options{
		MatchDir: func(path string) (copyrec.DirAction, error) {
			relative := util.GetRelativeToBaseFilepath(absFrom, path)
			switch {
			case matcher.IsPathMatched(relative):
				return copyrec.DirMatch, nil
			case matcher.ShouldGoThrough(relative):
				return copyrec.DirFallThrough, nil
			default:
				return copyrec.DirSkip, nil
			}
		},
		MatchFile: func(path string) (bool, error) {
			return matcher.IsPathMatched(util.GetRelativeToBaseFilepath(absFrom, path)), nil
		},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(copier.Run(ctx)).To(gomega.Succeed())
}

// normalizedImportDestination mirrors the backend's destination normalization.
func normalizedImportDestination(absFrom, absTo string) string {
	info, err := os.Lstat(absFrom)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	if info.IsDir() {
		return absTo
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return absTo
	}

	destination, err := os.Stat(absTo)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return absTo
	case err != nil:
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		return absTo
	case destination.IsDir():
		return filepath.Join(absTo, filepath.Base(absFrom))
	default:
		return absTo
	}
}

type importCase struct {
	source    []treeEntry
	target    []treeEntry
	matches   originalMatches
	scope     ImportScope
	afterCopy func(targetRoot string)
}

func (c importCase) run(ctx context.Context) (originalMatches, error) {
	sourceRoot, targetRoot := treeRoot(c.source), treeRoot(c.target)
	source, before := treeIndex(ctx, sourceRoot), treeIndex(ctx, targetRoot)
	runImport(ctx, sourceRoot, targetRoot, c.scope)
	if c.afterCopy != nil {
		c.afterCopy(targetRoot)
	}

	return importOriginalMatches(ctx, source, c.matches, before, treeIndex(ctx, targetRoot), c.scope)
}

func importedOK(ctx context.Context, c importCase) originalMatches {
	imported, err := c.run(ctx)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return imported
}

var _ = ginkgo.Describe("importing original matches", func() {
	ginkgo.It("maps a directory import onto the paths the copy leaves and ignores same-byte paths it did not import", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/bin/tool", "tool-bytes"),
				treeFile("opt/app/lib/libx.so", "libx-bytes"),
				treeFile("opt/other/thing", "tool-bytes"),
			},
			target: []treeEntry{treeFile("usr/local/tool", "tool-bytes")},
			matches: originalMatches{
				"/opt/app/bin/tool":    {{Source: "src-tool", Path: "bin/tool"}},
				"/opt/app/lib/libx.so": {{Source: "src-libx", Path: "lib/libx.so"}},
				"/opt/other/thing":     {{Source: "src-thing", Path: "share/thing"}},
			},
			scope: ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/bin/tool":    {{Source: "src-tool", Path: "bin/tool"}},
			"/dest/lib/libx.so": {{Source: "src-libx", Path: "lib/libx.so"}},
		}))
	})

	ginkgo.It("binds what this import carried and not same-byte paths the target already held", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/tool", "tool-bytes"),
				treeFile("opt/extra", "extra-bytes"),
			},
			// What an earlier import of the parent directory left behind.
			target: []treeEntry{treeFile("dest/opt/extra", "extra-bytes")},
			matches: originalMatches{
				"/opt/app/tool": {{Source: "src-tool", Path: "bin/tool"}},
				"/opt/extra":    {{Source: "src-extra", Path: "share/extra"}},
			},
			scope: ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/tool": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	ginkgo.It("puts a single file under an existing destination directory by its own name", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source:  []treeEntry{treeFile("opt/tool", "tool-bytes")},
			target:  []treeEntry{treeDir("dest")},
			matches: originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/tool", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/tool": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	ginkgo.It("keeps the destination name when the import names one", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source:  []treeEntry{treeFile("opt/tool", "tool-bytes")},
			target:  []treeEntry{treeDir("dest")},
			matches: originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/tool", ToPath: "/dest/renamed"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/renamed": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	ginkgo.It("prunes what the globs skip and follows a matched directory into its whole subtree", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/top.txt", "top-bytes"),
				treeFile("opt/app/keep/one.txt", "one-bytes"),
				treeFile("opt/app/keep/secret/hidden.txt", "hidden-bytes"),
				treeFile("opt/app/drop/two.txt", "two-bytes"),
			},
			target: []treeEntry{
				// Bytes an earlier stage left where the globs keep this import from writing.
				treeFile("dest/top.txt", "top-bytes"),
				treeFile("dest/drop/two.txt", "two-bytes"),
			},
			matches: originalMatches{
				"/opt/app/top.txt":                {{Source: "src", Path: "top.txt"}},
				"/opt/app/keep/one.txt":           {{Source: "src", Path: "keep/one.txt"}},
				"/opt/app/keep/secret/hidden.txt": {{Source: "src", Path: "keep/secret/hidden.txt"}},
				"/opt/app/drop/two.txt":           {{Source: "src", Path: "drop/two.txt"}},
			},
			scope: ImportScope{
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				IncludePaths: []string{"keep"},
				ExcludePaths: []string{"keep/secret"},
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/keep/one.txt":           {{Source: "src", Path: "keep/one.txt"}},
			"/dest/keep/secret/hidden.txt": {{Source: "src", Path: "keep/secret/hidden.txt"}},
		}))
	})

	ginkgo.It("follows a symlinked directory on the way to the import source", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("real/app/bin/tool", "tool-bytes"),
				treeLink("opt", "real"),
			},
			matches: originalMatches{"/real/app/bin/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/bin/tool": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	ginkgo.It("gives a symlinked import source no bytes at the destination", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/tool", "tool-bytes"),
				treeLink("opt/link", "app/tool"),
			},
			matches: originalMatches{"/opt/app/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/link", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.BeEmpty())
	})

	ginkgo.It("resolves a destination that stands behind a symlinked directory", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source:  []treeEntry{treeFile("opt/tool", "tool-bytes")},
			target:  []treeEntry{treeDir("real/dest"), treeLink("dest", "real/dest")},
			matches: originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/tool", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/real/dest/tool": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	ginkgo.It("drops imported paths the stage then removes or overwrites", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/a.txt", "a-bytes"),
				treeFile("opt/app/b.txt", "b-bytes"),
			},
			matches: originalMatches{
				"/opt/app/a.txt": {{Source: "src", Path: "a.txt"}},
				"/opt/app/b.txt": {{Source: "src", Path: "b.txt"}},
			},
			scope: ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.Remove(filepath.Join(targetRoot, "dest/a.txt"))).To(gomega.Succeed())
				gomega.Expect(os.WriteFile(filepath.Join(targetRoot, "dest/b.txt"), []byte("other-bytes"), 0o644)).To(gomega.Succeed())
			},
		})

		gomega.Expect(imported).To(gomega.BeEmpty())
	})

	ginkgo.It("carries the alternatives of an imported path in a settled order", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source:  []treeEntry{treeFile("opt/app/lib.so", "lib-bytes")},
			matches: originalMatches{"/opt/app/lib.so": {{Source: "src-b", Path: "lib/lib.so"}, {Source: "src-a", Path: "lib/lib.so"}}},
			scope:   ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
		})

		gomega.Expect(imported["/dest/lib.so"]).To(gomega.Equal([]originalBinding{
			{Source: "src-a", Path: "lib/lib.so"},
			{Source: "src-b", Path: "lib/lib.so"},
		}))
	})

	ginkgo.It("refuses a destination whose type the stage changed under the import", func(ctx ginkgo.SpecContext) {
		_, err := importCase{
			source:  []treeEntry{treeFile("opt/tool", "tool-bytes")},
			matches: originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/tool", ToPath: "/dest"},
			// Another import of the same stage can leave a directory where this one wrote a file.
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.Remove(filepath.Join(targetRoot, "dest"))).To(gomega.Succeed())
				gomega.Expect(os.MkdirAll(filepath.Join(targetRoot, "dest"), 0o755)).To(gomega.Succeed())
				gomega.Expect(os.WriteFile(filepath.Join(targetRoot, "dest/tool"), []byte("tool-bytes"), 0o644)).To(gomega.Succeed())
			},
		}.run(ctx)

		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses a destination whose symlinks the stage changed under the import", func(ctx ginkgo.SpecContext) {
		_, err := importCase{
			source:  []treeEntry{treeFile("opt/app/tool", "tool-bytes")},
			target:  []treeEntry{treeDir("real/dest"), treeLink("dest", "real/dest")},
			matches: originalMatches{"/opt/app/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{FromPath: "/opt/app", ToPath: "/dest"},
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.Remove(filepath.Join(targetRoot, "dest"))).To(gomega.Succeed())
				gomega.Expect(os.Symlink("other/dest", filepath.Join(targetRoot, "dest"))).To(gomega.Succeed())
			},
		}.run(ctx)

		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses an import source the image records as neither file nor directory", func(ctx ginkgo.SpecContext) {
		source := treeIndex(ctx, treeRoot([]treeEntry{treeFile("opt/app/tool", "tool-bytes")}))
		target := treeIndex(ctx, treeRoot(nil))

		_, err := importOriginalMatches(ctx, source, originalMatches{"/opt/app/tool": {{Source: "src", Path: "bin/tool"}}}, target, target, ImportScope{FromPath: "/opt/missing", ToPath: "/dest"})
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses incomplete inputs instead of answering from part of them", func(ctx ginkgo.SpecContext) {
		source := treeIndex(ctx, treeRoot([]treeEntry{treeFile("opt/app/tool", "tool-bytes")}))
		target := treeIndex(ctx, treeRoot(nil))
		matches := originalMatches{"/opt/app/tool": {{Source: "src", Path: "bin/tool"}}}
		scope := ImportScope{FromPath: "/opt/app", ToPath: "/dest"}

		_, err := importOriginalMatches(ctx, nil, matches, target, target, scope)
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))

		incomplete := *source
		incomplete.Incomplete = true
		_, err = importOriginalMatches(ctx, &incomplete, matches, target, target, scope)
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))

		withoutDirectories := *source
		withoutDirectories.Directories = nil
		_, err = importOriginalMatches(ctx, &withoutDirectories, matches, target, target, scope)
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("refuses matches the source image does not ground", func(ctx ginkgo.SpecContext) {
		source := treeIndex(ctx, treeRoot([]treeEntry{treeFile("opt/app/tool", "tool-bytes")}))
		target := treeIndex(ctx, treeRoot(nil))
		scope := ImportScope{FromPath: "/opt/app", ToPath: "/dest"}

		_, err := importOriginalMatches(ctx, source, originalMatches{"/opt/app/absent": {{Source: "src", Path: "bin/tool"}}}, target, target, scope)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("outside the indexed source")))

		_, err = importOriginalMatches(ctx, source, originalMatches{"/opt/app/tool": nil}, target, target, scope)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no binding")))

		_, err = importOriginalMatches(ctx, source, originalMatches{"/opt/app/tool": {{Source: "src"}}}, target, target, scope)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("incomplete binding")))
	})
})
