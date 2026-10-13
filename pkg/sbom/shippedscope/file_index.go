package shippedscope

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/werf/logboek"
)

type File struct {
	Digest string
	Size   int64
}

type FileIndex struct {
	Files    map[string]File
	Symlinks map[string]string
}

func IndexImageFiles(ctx context.Context, img v1.Image) (*FileIndex, error) {
	index := &FileIndex{
		Files:    make(map[string]File),
		Symlinks: make(map[string]string),
	}
	hardlinks := make(map[string]string)

	rootfs := mutate.Extract(img)
	defer rootfs.Close()

	reader := tar.NewReader(rootfs)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read image filesystem: %w", err)
		}

		name := rootedPath(header.Name)

		switch header.Typeflag {
		case tar.TypeReg:
			hasher := sha256.New()
			if _, err := io.Copy(hasher, reader); err != nil {
				return nil, fmt.Errorf("hash %q: %w", name, err)
			}

			index.Files[name] = File{
				Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
				Size:   header.Size,
			}
		case tar.TypeSymlink:
			index.Symlinks[name] = header.Linkname
		case tar.TypeLink:
			hardlinks[name] = rootedPath(header.Linkname)
		}
	}

	for name, target := range hardlinks {
		file, ok := index.Files[target]
		if !ok {
			logboek.Context(ctx).Debug().LogF("hardlink %q points to %q, which the image filesystem does not contain\n", name, target)
			continue
		}

		index.Files[name] = file
	}

	return index, nil
}

func rootedPath(name string) string {
	return "/" + strings.TrimPrefix(path.Clean(name), "/")
}
