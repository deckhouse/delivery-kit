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
})
