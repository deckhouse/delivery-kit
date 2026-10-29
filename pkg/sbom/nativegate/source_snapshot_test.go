package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"maps"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func fixtureOriginal(files map[string]string) *original.OriginalPackage {
	pkg, err := original.NewOriginalPackage(fixtureImage(files))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(pkg.Complete()).To(gomega.BeTrue())

	return pkg
}

func fixtureLayerBytes(files map[string]string) []byte {
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	for name, body := range files {
		gomega.Expect(tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: fixtureFileMode(name), Size: int64(len(body))})).To(gomega.Succeed())
		_, err := tw.Write([]byte(body))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(tw.Close()).To(gomega.Succeed())

	return buffer.Bytes()
}

// mutableLayer serves whatever bytes body holds at the moment it is read, so a layer can
// change after the package indexed it — what a real registry blob served twice may do.
type mutableLayer struct {
	v1.Layer
	body *[]byte
}

func (l mutableLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(*l.body)), nil
}

func fixtureMutableOriginal(files map[string]string) (*original.OriginalPackage, func(old, new string)) {
	body := fixtureLayerBytes(files)
	base, err := tarball.LayerFromReader(bytes.NewReader(body))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, mutableLayer{Layer: base, body: &body})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	pkg, err := original.NewOriginalPackage(image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(pkg.Complete()).To(gomega.BeTrue())

	return pkg, func(old, new string) {
		gomega.Expect(len(old)).To(gomega.Equal(len(new)))
		replaced := bytes.Replace(body, []byte(old), []byte(new), 1)
		gomega.Expect(replaced).NotTo(gomega.Equal(body))
		body = replaced
	}
}

// fixtureOriginalWithSymlink ships one regular file plus a symlink the package itself cannot
// resolve — what a package split across two images looks like from inside one of them.
func fixtureOriginalWithSymlink(files map[string]string, link, target string) *original.OriginalPackage {
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	for name, body := range files {
		gomega.Expect(tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: fixtureFileMode(name), Size: int64(len(body))})).To(gomega.Succeed())
		_, err := tw.Write([]byte(body))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(link, "/"), Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777})).To(gomega.Succeed())
	gomega.Expect(tw.Close()).To(gomega.Succeed())

	layer, err := tarball.LayerFromReader(bytes.NewReader(buffer.Bytes()))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	pkg, err := original.NewOriginalPackage(image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(pkg.Complete()).To(gomega.BeTrue())

	return pkg
}

var _ = ginkgo.Describe("binding an initial snapshot to its originals", func() {
	ginkgo.It("binds only files the snapshot ships at the original's own path", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes", "/etc/conf": "edited-bytes", "/opt/own": "own-bytes"})
		originals := map[string]*original.OriginalPackage{
			"src-tool": fixtureOriginal(map[string]string{
				"/opt/tool":   "tool-bytes",
				"/etc/conf":   "conf-bytes",
				"/opt/unused": "unused-bytes",
			}),
		}

		matches, err := matchSnapshotOriginals(context.Background(), index, originals)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(matches).To(gomega.Equal(originalMatches{
			"/opt/tool": {{Source: "src-tool", Path: "opt/tool"}},
		}))
	})

	ginkgo.It("does not search the snapshot for original bytes that moved", func() {
		index := fixtureIndex(map[string]string{"/usr/bin/tool": "tool-bytes"})
		originals := map[string]*original.OriginalPackage{"src-tool": fixtureOriginal(map[string]string{"/opt/tool": "tool-bytes"})}

		matches, err := matchSnapshotOriginals(context.Background(), index, originals)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(matches).To(gomega.BeEmpty())
	})

	ginkgo.It("leaves a path two originals ship identically as alternatives", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		originals := map[string]*original.OriginalPackage{
			"src-b": fixtureOriginal(map[string]string{"/opt/tool": "tool-bytes"}),
			"src-a": fixtureOriginal(map[string]string{"/opt/tool": "tool-bytes"}),
		}

		matches, err := matchSnapshotOriginals(context.Background(), index, originals)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(matches["/opt/tool"]).To(gomega.Equal([]originalBinding{
			{Source: "src-a", Path: "opt/tool"},
			{Source: "src-b", Path: "opt/tool"},
		}))

		_, err = uniqueOriginalBinding(matches["/opt/tool"])
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("binds what the snapshot ships although the original dangles a link into another package", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		pkg := fixtureOriginalWithSymlink(map[string]string{"/opt/tool": "tool-bytes"}, "/opt/plugin", "/opt/other-package/plugin")

		matches, err := matchSnapshotOriginals(context.Background(), index, map[string]*original.OriginalPackage{"src-tool": pkg})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(matches).To(gomega.Equal(originalMatches{
			"/opt/tool": {{Source: "src-tool", Path: "opt/tool"}},
		}))
	})

	ginkgo.It("fails when the snapshot wants the path the original cannot resolve", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		file := index.Files["/opt/tool"]
		pkg := fixtureOriginalWithSymlink(map[string]string{"/opt/tool": "tool-bytes"}, "/opt/plugin", "/opt/other-package/plugin")

		err := verifyOriginalFiles(context.Background(), pkg, map[string]shippedscope.File{"opt/plugin": file})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("opt/plugin")))

		index.Files["/opt/plugin"] = file
		matches, err := matchSnapshotOriginals(context.Background(), index, map[string]*original.OriginalPackage{"src-tool": pkg})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("opt/plugin")))
		gomega.Expect(matches).To(gomega.BeNil())
	})

	ginkgo.It("fails when the original's bytes do not survive the read", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		pkg, tamper := fixtureMutableOriginal(map[string]string{"/opt/tool": "tool-bytes"})

		matches, err := matchSnapshotOriginals(context.Background(), index, map[string]*original.OriginalPackage{"src-tool": pkg})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(matches))).To(gomega.Equal([]string{"/opt/tool"}))

		tamper("tool-bytes", "TOOL-bytes")

		matches, err = matchSnapshotOriginals(context.Background(), index, map[string]*original.OriginalPackage{"src-tool": pkg})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash mismatch")))
		gomega.Expect(matches).To(gomega.BeNil())
	})

	ginkgo.It("fails when the snapshot and the original disagree on a file's length", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		file := index.Files["/opt/tool"]
		index.Files["/opt/tool"] = shippedscope.File{Digest: file.Digest, Size: file.Size + 1}

		matches, err := matchSnapshotOriginals(context.Background(), index, map[string]*original.OriginalPackage{
			"src-tool": fixtureOriginal(map[string]string{"/opt/tool": "tool-bytes"}),
		})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("bytes against")))
		gomega.Expect(matches).To(gomega.BeNil())
	})

	ginkgo.It("reports no data for a snapshot or an original it cannot trust", func() {
		index := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		incompleteIndex := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes"})
		incompleteIndex.Incomplete = true
		pkg := fixtureOriginal(map[string]string{"/opt/tool": "tool-bytes"})

		for _, call := range []struct {
			index     *shippedscope.FileIndex
			originals map[string]*original.OriginalPackage
		}{
			{nil, map[string]*original.OriginalPackage{"src-tool": pkg}},
			{incompleteIndex, map[string]*original.OriginalPackage{"src-tool": pkg}},
			{index, map[string]*original.OriginalPackage{"src-tool": nil}},
			{index, map[string]*original.OriginalPackage{"src-tool": {}}},
		} {
			matches, err := matchSnapshotOriginals(context.Background(), call.index, call.originals)
			gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
			gomega.Expect(matches).To(gomega.BeNil())
		}
	})
})
