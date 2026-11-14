package stage

import (
	"archive/tar"
	"bytes"
	"context"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Git original files for SBOM", func() {
	ginkgo.DescribeTable("hashes the exact destination file", func(directory bool, destination, expected string) {
		var body bytes.Buffer
		writer := tar.NewWriter(&body)
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: "source.c", Mode: 0o644, Size: 3})).To(gomega.Succeed())
		_, err := writer.Write([]byte("abc"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(writer.Close()).To(gomega.Succeed())
		files, err := gitArchiveSourceFiles(context.Background(), &body, destination, directory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(files.Files).To(gomega.Equal(map[string]string{expected: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}))
	}, ginkgo.Entry("directory mapping", true, "/src", "/src/source.c"), ginkgo.Entry("renamed file mapping", false, "/src/main.c", "/src/main.c"))
	ginkgo.It("refuses a path escaping the git mapping", func() {
		var body bytes.Buffer
		writer := tar.NewWriter(&body)
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644})).To(gomega.Succeed())
		gomega.Expect(writer.Close()).To(gomega.Succeed())
		_, err := gitArchiveSourceFiles(context.Background(), &body, "/src", true)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("../escape")))
	})
})
