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
})
