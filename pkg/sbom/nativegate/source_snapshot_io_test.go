package nativegate

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// layerIO counts what reaching the original blob actually costs: a registry serves the
// whole layer for every Uncompressed call, so these are the numbers an SDK-sized package
// multiplies.
type layerIO struct {
	opens int
	read  int64
}

type countingLayer struct {
	v1.Layer
	io *layerIO
}

func (l countingLayer) Uncompressed() (io.ReadCloser, error) {
	body, err := l.Layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	l.io.opens++

	return &countingReader{ReadCloser: body, io: l.io}, nil
}

type countingReader struct {
	io.ReadCloser
	io *layerIO
}

func (r *countingReader) Read(b []byte) (int, error) {
	n, err := r.ReadCloser.Read(b)
	r.io.read += int64(n)

	return n, err
}

func fixtureCountedOriginal(files map[string]string) (*original.OriginalPackage, *layerIO) {
	base, err := fixtureLayer(fixtureLayerBytes(files))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	counted := &layerIO{}
	image, err := mutate.AppendLayers(empty.Image, countingLayer{Layer: base, io: counted})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	pkg, err := original.NewOriginalPackage(image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(pkg.Complete()).To(gomega.BeTrue())
	// Indexing reads every layer once up front; the binding cost is what follows it.
	*counted = layerIO{}

	return pkg, counted
}

var _ = ginkgo.Describe("the blob traffic binding a snapshot costs", func() {
	ginkgo.It("reads the original layer once however many files the snapshot binds", func() {
		files := make(map[string]string, 64)
		for i := range 64 {
			files[fmt.Sprintf("/opt/pkg/file-%02d", i)] = strings.Repeat(fmt.Sprintf("body-%02d;", i), 16*1024/9)
		}
		index := fixtureIndex(files)
		pkg, counted := fixtureCountedOriginal(files)

		start := time.Now()
		matches, err := matchSnapshotOriginals(context.Background(), index, map[string]*original.OriginalPackage{"src-pkg": pkg})
		elapsed := time.Since(start)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(matches).To(gomega.HaveLen(len(files)))
		ginkgo.GinkgoWriter.Printf("binding %d files: %d layer opens, %d bytes read, %s\n", len(files), counted.opens, counted.read, elapsed)
		gomega.Expect(counted.opens).To(gomega.Equal(1))
		gomega.Expect(counted.read).To(gomega.BeNumerically("<", 2*int64(len(files))*16*1024))
	})
})
