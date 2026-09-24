package container_backend

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("dirTarExtractor", func() {
	type entry struct {
		name     string
		typeflag byte
		content  string
		linkname string
	}

	// buildTar mimics a `docker cp /app/node_modules` stream: every entry is prefixed
	// with the copied directory's base name.
	buildTar := func(entries []entry) *tar.Reader {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Linkname: e.linkname}
			if e.typeflag == tar.TypeReg {
				hdr.Size = int64(len(e.content))
			}
			Expect(tw.WriteHeader(hdr)).To(Succeed())
			if e.typeflag == tar.TypeReg {
				_, err := tw.Write([]byte(e.content))
				Expect(err).To(Succeed())
			}
		}
		Expect(tw.Close()).To(Succeed())
		return tar.NewReader(&buf)
	}

	extractAll := func(tr *tar.Reader, destDir string, fileNames []string) {
		ex := newDirTarExtractor("/app/node_modules", destDir, fileNames)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			Expect(err).To(Succeed())
			Expect(ex.extract(tr, hdr)).To(Succeed())
		}
		Expect(ex.resolveSymlinks()).To(Succeed())
	}

	It("writes only the listed manifests, preserving scoped and nested package layout", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/", typeflag: tar.TypeDir},
			{name: "node_modules/is-number/package.json", typeflag: tar.TypeReg, content: `{"license":"MIT"}`},
			{name: "node_modules/is-number/index.js", typeflag: tar.TypeReg, content: "module.exports = 1"},
			{name: "node_modules/@babel/core/package.json", typeflag: tar.TypeReg, content: `{"license":"MIT"}`},
			{name: "node_modules/a/node_modules/b/package.json", typeflag: tar.TypeReg, content: `{"license":"ISC"}`},
			{name: "node_modules/.bin/tsc", typeflag: tar.TypeSymlink, linkname: "../typescript/bin/tsc"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		for _, p := range []string{
			"is-number/package.json",
			"@babel/core/package.json",
			"a/node_modules/b/package.json",
		} {
			_, err := os.Stat(filepath.Join(destDir, p))
			Expect(err).To(Succeed(), "manifest %s must be extracted at its relative path", p)
		}

		_, err := os.Stat(filepath.Join(destDir, "is-number", "index.js"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "installed code must not be copied")
		_, err = os.Stat(filepath.Join(destDir, ".bin", "tsc"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "symlinks to files are not materialized")
	})

	It("resolves pnpm's package symlinks into the .pnpm store so the flat path exists", func() {
		// pnpm installs packages under .pnpm/<pkg>@<ver>/node_modules/<pkg> and exposes
		// them as symlinks at node_modules/<pkg>. syft's javascript-lock-cataloger reads
		// node_modules/<pkg>/package.json, which docker cp delivers only as a symlink entry.
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/lodash", typeflag: tar.TypeSymlink, linkname: ".pnpm/lodash@4.17.21/node_modules/lodash"},
			{name: "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json", typeflag: tar.TypeReg, content: `{"name":"lodash","license":"MIT"}`},
			{name: "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/lodash.js", typeflag: tar.TypeReg, content: "js"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		manifest, err := os.ReadFile(filepath.Join(destDir, "lodash", "package.json"))
		Expect(err).To(Succeed(), "the symlinked package must be readable at its flat path")
		Expect(string(manifest)).To(ContainSubstring(`"license":"MIT"`))

		_, err = os.Stat(filepath.Join(destDir, "lodash", "lodash.js"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "the name filter also applies through the resolved link")
	})

	It("resolves an absolute symlink target against the source directory", func() {
		// Some layouts (e.g. hoisted stores) express node_modules/<pkg> as an absolute
		// symlink into the same tree; docker cp emits its Linkname verbatim, absolute.
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/is-number", typeflag: tar.TypeSymlink, linkname: "/app/node_modules/.store/is-number"},
			{name: "node_modules/.store/is-number/package.json", typeflag: tar.TypeReg, content: `{"name":"is-number","license":"MIT"}`},
		})

		extractAll(tr, destDir, []string{"package.json"})

		manifest, err := os.ReadFile(filepath.Join(destDir, "is-number", "package.json"))
		Expect(err).To(Succeed(), "an absolute link into the tree must resolve to its flat path")
		Expect(string(manifest)).To(ContainSubstring(`"license":"MIT"`))
	})

	It("drops an absolute symlink pointing outside the source directory", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/evil", typeflag: tar.TypeSymlink, linkname: "/etc"},
			{name: "node_modules/x/package.json", typeflag: tar.TypeReg, content: "{}"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		_, err := os.Stat(filepath.Join(destDir, "evil"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "an absolute link outside the copied dir must not pull in host files")
	})

	It("ignores a symlink whose target was not extracted or points outside the tree", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/dangling", typeflag: tar.TypeSymlink, linkname: ".pnpm/missing/node_modules/missing"},
			{name: "node_modules/escape", typeflag: tar.TypeSymlink, linkname: "../../../../etc"},
			{name: "node_modules/x/package.json", typeflag: tar.TypeReg, content: "{}"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		_, err := os.Stat(filepath.Join(destDir, "dangling"))
		Expect(os.IsNotExist(err)).To(BeTrue())
		_, err = os.Stat(filepath.Join(destDir, "escape"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "a link escaping the tree must not pull in host files")
	})

	It("drops a relative symlink escaping the tree instead of rebasing it onto an in-tree directory", func() {
		// /app/node_modules/is-number -> ../store/is-number really points at
		// /app/store/is-number, which was not copied. Cleaning "../store/is-number" under
		// an anchored root would turn it into the unrelated in-tree
		// node_modules/store/is-number and report that package's license instead.
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/is-number", typeflag: tar.TypeSymlink, linkname: "../store/is-number"},
			{name: "node_modules/store/is-number/package.json", typeflag: tar.TypeReg, content: `{"name":"is-number","license":"Apache-2.0"}`},
		})

		extractAll(tr, destDir, []string{"package.json"})

		_, err := os.Stat(filepath.Join(destDir, "is-number"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "an escaping link must not be substituted with the colliding in-tree directory")
		_, err = os.Stat(filepath.Join(destDir, "store", "is-number", "package.json"))
		Expect(err).To(Succeed(), "the genuine in-tree manifest is still extracted at its own path")
	})

	It("resolves a chain of directory symlinks regardless of the order links were recorded", func() {
		// is-number -> alias -> .store/is-number. Resolving links in a single pass over an
		// unordered set would skip is-number whenever it is visited before alias has been
		// materialized, so the outcome depended on iteration order. Repeat to cover orders.
		for i := 0; i < 20; i++ {
			destDir := GinkgoT().TempDir()
			tr := buildTar([]entry{
				{name: "node_modules/is-number", typeflag: tar.TypeSymlink, linkname: "alias"},
				{name: "node_modules/alias", typeflag: tar.TypeSymlink, linkname: ".store/is-number"},
				{name: "node_modules/.store/is-number/package.json", typeflag: tar.TypeReg, content: `{"name":"is-number","license":"MIT"}`},
			})

			extractAll(tr, destDir, []string{"package.json"})

			manifest, err := os.ReadFile(filepath.Join(destDir, "is-number", "package.json"))
			Expect(err).To(Succeed(), "iteration %d: the head of the chain must resolve to the stored manifest", i)
			Expect(string(manifest)).To(ContainSubstring(`"license":"MIT"`))
		}
	})

	It("drops a chain whose intermediate link escapes the tree instead of following it outside", func() {
		// is-number -> alias -> ../outside. The escaping hop is dropped on record, so the
		// head of the chain must resolve to nothing rather than to a substituted directory.
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/is-number", typeflag: tar.TypeSymlink, linkname: "alias"},
			{name: "node_modules/alias", typeflag: tar.TypeSymlink, linkname: "../outside"},
			{name: "node_modules/outside/package.json", typeflag: tar.TypeReg, content: `{"name":"is-number","license":"Apache-2.0"}`},
		})

		extractAll(tr, destDir, []string{"package.json"})

		for _, p := range []string{"is-number", "alias"} {
			_, err := os.Stat(filepath.Join(destDir, p))
			Expect(os.IsNotExist(err)).To(BeTrue(), "link %s must not be materialized through an escaping hop", p)
		}
	})

	It("terminates on a symlink cycle without materializing either link", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/a", typeflag: tar.TypeSymlink, linkname: "b"},
			{name: "node_modules/b", typeflag: tar.TypeSymlink, linkname: "a"},
			{name: "node_modules/x/package.json", typeflag: tar.TypeReg, content: "{}"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		for _, p := range []string{"a", "b"} {
			_, err := os.Stat(filepath.Join(destDir, p))
			Expect(os.IsNotExist(err)).To(BeTrue(), "link %s in a cycle resolves to nothing", p)
		}
	})

	It("extracts every regular file when no name filter is given", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/x/package.json", typeflag: tar.TypeReg, content: "{}"},
			{name: "node_modules/x/index.js", typeflag: tar.TypeReg, content: "1"},
		})

		extractAll(tr, destDir, nil)

		_, err := os.Stat(filepath.Join(destDir, "x", "index.js"))
		Expect(err).To(Succeed())
	})

	It("keeps a crafted path-traversal entry inside destDir", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{name: "node_modules/../../escape/package.json", typeflag: tar.TypeReg, content: "{}"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		_, err := os.Stat(filepath.Join(destDir, "escape", "package.json"))
		Expect(err).To(Succeed(), "the entry must be rebased under destDir, not written outside it")
		_, err = os.Stat(filepath.Join(filepath.Dir(filepath.Dir(destDir)), "escape", "package.json"))
		Expect(os.IsNotExist(err)).To(BeTrue())
	})

	It("copies license files of a go module cache entry by case-insensitive pattern", func() {
		destDir := GinkgoT().TempDir()
		ex := newDirTarExtractor("/go/pkg/mod/github.com/samber/lo@v1.47.0", destDir, []string{"license*", "copying*", "notice*"})
		tr := buildTar([]entry{
			{name: "lo@v1.47.0/LICENSE", typeflag: tar.TypeReg, content: "MIT"},
			{name: "lo@v1.47.0/License.md", typeflag: tar.TypeReg, content: "MIT"},
			{name: "lo@v1.47.0/COPYING", typeflag: tar.TypeReg, content: "GPL"},
			{name: "lo@v1.47.0/NOTICE.txt", typeflag: tar.TypeReg, content: "n"},
			{name: "lo@v1.47.0/map.go", typeflag: tar.TypeReg, content: "package lo"},
			{name: "lo@v1.47.0/README.md", typeflag: tar.TypeReg, content: "readme"},
		})
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			Expect(err).To(Succeed())
			Expect(ex.extract(tr, hdr)).To(Succeed())
		}
		Expect(ex.resolveSymlinks()).To(Succeed())

		for _, p := range []string{"LICENSE", "License.md", "COPYING", "NOTICE.txt"} {
			_, err := os.Stat(filepath.Join(destDir, p))
			Expect(err).To(Succeed(), "%s must be copied", p)
		}
		for _, p := range []string{"map.go", "README.md"} {
			_, err := os.Stat(filepath.Join(destDir, p))
			Expect(os.IsNotExist(err)).To(BeTrue(), "%s (module source) must not be copied", p)
		}
	})
})

var _ = Describe("matchesAnyFileNamePattern", func() {
	DescribeTable("shell patterns, case-insensitive",
		func(name string, patterns []string, expected bool) {
			Expect(matchesAnyFileNamePattern(name, patterns)).To(Equal(expected))
		},
		Entry("no patterns matches everything", "anything.go", nil, true),
		Entry("exact name", "package.json", []string{"package.json"}, true),
		Entry("exact name is case-insensitive", "PACKAGE.JSON", []string{"package.json"}, true),
		Entry("prefix glob", "LICENSE.md", []string{"license*"}, true),
		Entry("prefix glob, other case", "license.txt", []string{"LICENSE*"}, true),
		Entry("any of several", "COPYING", []string{"license*", "copying*"}, true),
		Entry("no match", "index.js", []string{"package.json", "license*"}, false),
		Entry("pattern anchors at start", "MIT-LICENSE", []string{"license*"}, false),
		Entry("character class covers the British spelling", "LICEN"+"CE.txt", []string{"licen[cs]e*"}, true),
		Entry("character class covers the American spelling", "license.md", []string{"licen[cs]e*"}, true),
	)
})
