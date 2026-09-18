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

var _ = Describe("extractDirTarEntry", func() {
	type entry struct {
		name     string
		typeflag byte
		content  string
	}

	// buildTar mimics a `docker cp /app/node_modules` stream: every entry is prefixed
	// with the copied directory's base name.
	buildTar := func(entries []entry) *tar.Reader {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Size: int64(len(e.content))}
			if e.typeflag == tar.TypeSymlink {
				hdr.Linkname = "../real/package.json"
				hdr.Size = 0
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
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				return
			}
			Expect(err).To(Succeed())
			Expect(extractDirTarEntry(tr, hdr, "/app/node_modules", destDir, fileNames)).To(Succeed())
		}
	}

	It("writes only the listed manifests, preserving scoped and nested package layout", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{"node_modules/", tar.TypeDir, ""},
			{"node_modules/is-number/package.json", tar.TypeReg, `{"license":"MIT"}`},
			{"node_modules/is-number/index.js", tar.TypeReg, "module.exports = 1"},
			{"node_modules/@babel/core/package.json", tar.TypeReg, `{"license":"MIT"}`},
			{"node_modules/a/node_modules/b/package.json", tar.TypeReg, `{"license":"ISC"}`},
			{"node_modules/.bin/tsc", tar.TypeSymlink, ""},
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
		Expect(os.IsNotExist(err)).To(BeTrue(), "symlinks must be skipped")
	})

	It("extracts every regular file when no name filter is given", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{"node_modules/x/package.json", tar.TypeReg, "{}"},
			{"node_modules/x/index.js", tar.TypeReg, "1"},
		})

		extractAll(tr, destDir, nil)

		_, err := os.Stat(filepath.Join(destDir, "x", "index.js"))
		Expect(err).To(Succeed())
	})

	It("keeps a crafted path-traversal entry inside destDir", func() {
		destDir := GinkgoT().TempDir()
		tr := buildTar([]entry{
			{"node_modules/../../escape/package.json", tar.TypeReg, "{}"},
		})

		extractAll(tr, destDir, []string{"package.json"})

		_, err := os.Stat(filepath.Join(destDir, "escape", "package.json"))
		Expect(err).To(Succeed(), "the entry must be rebased under destDir, not written outside it")
		_, err = os.Stat(filepath.Join(filepath.Dir(filepath.Dir(destDir)), "escape", "package.json"))
		Expect(os.IsNotExist(err)).To(BeTrue())
	})
})
