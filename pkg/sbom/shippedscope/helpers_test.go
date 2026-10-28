package shippedscope

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	body     string
}

func regularFile(name, body string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeReg, body: body}
}

func symlink(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeSymlink, linkname: target}
}

func hardlink(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeLink, linkname: target}
}

func whiteout(name string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeReg}
}

func directory(name string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeDir}
}

func layerOf(entries ...tarEntry) (v1.Layer, error) {
	var buf bytes.Buffer

	writer := tar.NewWriter(&buf)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
			Size:     int64(len(entry.body)),
			Mode:     0o644,
		}
		if entry.typeflag != tar.TypeReg {
			header.Size = 0
		}

		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if header.Size > 0 {
			if _, err := io.WriteString(writer, entry.body); err != nil {
				return nil, err
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	contents := buf.Bytes()

	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(contents)), nil
	})
}

func imageOf(layers ...[]tarEntry) (v1.Image, error) {
	img := empty.Image
	for _, entries := range layers {
		layer, err := layerOf(entries...)
		if err != nil {
			return nil, err
		}

		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			return nil, err
		}
	}

	return img, nil
}

var _ v1.Layer = (*countedLayer)(nil)

type countedLayer struct {
	v1.Layer
	opens int
}

func (layer *countedLayer) Uncompressed() (io.ReadCloser, error) {
	layer.opens++
	return layer.Layer.Uncompressed()
}

func digestOf(body string) string {
	sum := sha256.Sum256([]byte(body))

	return "sha256:" + hex.EncodeToString(sum[:])
}

func filesetOf(filesets *Filesets, ecosystem Ecosystem, name, version string) *Fileset {
	for i, fileset := range filesets.Filesets {
		if fileset.Ecosystem == ecosystem && fileset.Name == name && fileset.Version == version {
			return &filesets.Filesets[i]
		}
	}

	return nil
}

func componentOf(purl string, occurrences ...cdx.EvidenceOccurrence) cdx.Component {
	comp := cdx.Component{BOMRef: purl, PackageURL: purl, Name: purl}
	if len(occurrences) > 0 {
		comp.Evidence = &cdx.Evidence{Occurrences: &occurrences}
	}
	return comp
}

func filesetsOf(index *FileIndex) *Filesets {
	return &Filesets{Index: index}
}

func caseSensitiveGoBinary(ctx context.Context) []byte {
	ginkgo.GinkgoHelper()
	root := ginkgo.GinkgoT().TempDir()
	files := map[string]string{
		"lib/go.mod":  "module example.test/Owner/Library\n\ngo 1.24\n",
		"lib/lib.go":  "package library\n\nfunc Value() string { return \"case-sensitive dependency\" }\n",
		"app/go.mod":  "module example.test/app\n\ngo 1.24\n\nrequire example.test/Owner/Library v1.0.0\n\nreplace example.test/Owner/Library => ../lib\n",
		"app/main.go": "package main\n\nimport \"example.test/Owner/Library\"\n\nfunc main() { println(library.Value()) }\n",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		gomega.Expect(os.MkdirAll(filepath.Dir(path), 0o755)).To(gomega.Succeed())
		gomega.Expect(os.WriteFile(path, []byte(body), 0o644)).To(gomega.Succeed())
	}
	outputPath := filepath.Join(root, "app.bin")
	command := exec.CommandContext(ctx, "go", "build", "-o", outputPath, ".")
	command.Dir = filepath.Join(root, "app")
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOWORK=off", "GOPROXY=off")
	output, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(output))
	binary, err := os.ReadFile(outputPath)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return binary
}
