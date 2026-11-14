package nativegate

import (
	"context"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("source import projection", func() {
	ginkgo.It("preserves the expected target of a link inside an imported directory", func() {
		ctx := context.Background()
		source, err := shippedscope.IndexImageFiles(ctx, fixtureImageWithLinks(map[string][]byte{"/src/data": []byte("a")}, map[string]string{"/src/current": "data"}))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		before, err := shippedscope.IndexImageFiles(ctx, fixtureImage(nil))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		after, err := shippedscope.IndexImageFiles(ctx, fixtureImageWithLinks(map[string][]byte{"/out/data": []byte("a")}, map[string]string{"/out/current": "data"}))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		links, err := ProjectImageSymlinks(ctx, source, before, after, ImportScope{FromPath: "/src", ToPath: "/out"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(links).To(gomega.Equal(map[string]string{"/out/current": "data"}))
	})
	ginkgo.DescribeTable("uses the actual copy backend filter semantics", func(backend ImportBackend, expected int) {
		ctx := context.Background()
		source, err := shippedscope.IndexImageFiles(ctx, fixtureImage(map[string][]byte{"/src/dir/keep": []byte("a"), "/src/dir/drop": []byte("b")}))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		before, err := shippedscope.IndexImageFiles(ctx, fixtureImage(nil))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		after, err := shippedscope.IndexImageFiles(ctx, fixtureImage(map[string][]byte{"/out/dir/keep": []byte("a"), "/out/dir/drop": []byte("b")}))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		originals := []Original{{Path: "/src/dir/keep"}, {Path: "/src/dir/drop"}}
		projected, err := ProjectImageOriginals(ctx, originals, source, before, after, ImportScope{Backend: backend, FromPath: "/src", ToPath: "/out", IncludePaths: []string{"dir"}, ExcludePaths: []string{"dir/drop"}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(projected).To(gomega.HaveLen(expected))
		gomega.Expect(projected).To(gomega.ContainElement(gomega.HaveField("Path", "/out/dir/keep")))
	}, ginkgo.Entry("copy-recurse", ImportBackendCopyRecurse, 2), ginkgo.Entry("rsync", ImportBackendRsync, 1))
	ginkgo.It("rejects a changed destination symlink", func() {
		ctx := context.Background()
		index, err := shippedscope.IndexImageFiles(ctx, fixtureImage(map[string][]byte{"/src/file": []byte("a")}))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		before := &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{"/out": "/old"}, Directories: map[string]struct{}{"/": {}}}
		after := &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{"/out": "/new"}, Directories: map[string]struct{}{"/": {}}}
		_, err = ProjectImageOriginals(ctx, []Original{{Path: "/src/file"}}, index, before, after, ImportScope{FromPath: "/src", ToPath: "/out"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("links the stage changed")))
	})
})
