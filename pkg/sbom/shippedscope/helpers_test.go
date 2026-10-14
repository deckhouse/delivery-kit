package shippedscope

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
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
