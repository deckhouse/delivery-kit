package container_backend

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("BuildahBackend ReadFileFromImage path resolution", func() {
	It("reads a regular file by its container path", func() {
		root := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(root, "out"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(root, "out", "x"), []byte("content"), 0o644)).To(Succeed())

		Expect(readRegularFileFromRoot(root, "/out/x")).To(Equal([]byte("content")))
	})

	It("follows an absolute symlink against the container root, not the host", func() {
		base := GinkgoT().TempDir()
		root := filepath.Join(base, "root")
		Expect(os.MkdirAll(filepath.Join(root, "out"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(root, "etc"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(root, "etc", "secret"), []byte("container"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(base, "secret"), []byte("host"), 0o644)).To(Succeed())
		Expect(os.Symlink("/etc/secret", filepath.Join(root, "out", "x"))).To(Succeed())
		Expect(os.Symlink("../../secret", filepath.Join(root, "out", "y"))).To(Succeed())

		Expect(readRegularFileFromRoot(root, "/out/x")).To(Equal([]byte("container")))

		_, err := readRegularFileFromRoot(root, "/out/y")
		Expect(err).To(MatchError(os.ErrNotExist))
	})

	It("rejects anything but a regular file", func() {
		root := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(root, "out"), 0o755)).To(Succeed())
		Expect(os.Symlink("/nowhere", filepath.Join(root, "out", "dangling"))).To(Succeed())

		_, err := readRegularFileFromRoot(root, "/out")
		Expect(err).To(MatchError("not a regular file"))

		_, err = readRegularFileFromRoot(root, "/out/dangling")
		Expect(err).To(MatchError(os.ErrNotExist))
	})

	Describe("Glob", func() {
		It("lists the regular files under the resolved base directory that the pattern matches, without following symlinks", func(ctx SpecContext) {
			base := GinkgoT().TempDir()
			root := filepath.Join(base, "root")
			modules := filepath.Join(root, "usr", "lib", "modules", "6.12", "kernel")
			Expect(os.MkdirAll(filepath.Join(modules, "net"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(modules, "a.ko"), []byte("a"), 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(modules, "net", "b.ko"), []byte("b"), 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(modules, "net", "b.ko.d"), []byte("d"), 0o644)).To(Succeed())
			Expect(os.Symlink("a.ko", filepath.Join(modules, "link.ko"))).To(Succeed())
			Expect(os.MkdirAll(filepath.Join(base, "host"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(base, "host", "c.ko"), []byte("host"), 0o644)).To(Succeed())
			Expect(os.Symlink("../../../../../host", filepath.Join(modules, "escape"))).To(Succeed())
			Expect(os.Symlink("/usr/lib", filepath.Join(root, "lib"))).To(Succeed())

			reader := &buildahImageReader{container: &containerDesc{RootMount: root}}

			Expect(reader.Glob(ctx, "/lib/modules/**/*.ko")).To(Equal([]string{
				"/lib/modules/6.12/kernel/a.ko",
				"/lib/modules/6.12/kernel/net/b.ko",
			}), "the base directory is resolved through the container's own symlink, below it symlinks are not followed")
		})

		It("matches nothing when the base directory does not exist", func(ctx SpecContext) {
			reader := &buildahImageReader{container: &containerDesc{RootMount: GinkgoT().TempDir()}}

			Expect(reader.Glob(ctx, "/out/**/*.ko")).To(BeEmpty())
		})
	})
})
