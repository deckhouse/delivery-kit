package nativegate

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func ProjectSources(ctx context.Context, img v1.Image, ranges shippedscope.ProducedLayers) (map[string]string, error) {
	if !ranges.Known {
		return nil, fmt.Errorf("unknown Git source layers")
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	sources := map[string]string{}
	for _, r := range ranges.Ranges {
		if r.Start < 0 || r.End < r.Start || r.End > len(layers) {
			return nil, fmt.Errorf("invalid Git layer range")
		}
		for index := r.Start; index < r.End; index++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			reader, err := layers[index].Uncompressed()
			if err != nil {
				return nil, err
			}
			err = readSources(tar.NewReader(reader), sources, "/", "/")
			closeErr := reader.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, closeErr
			}
		}
	}
	return sources, nil
}

func ReadSourceArchive(ctx context.Context, reader io.Reader, destination, repositoryPath string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sources := map[string]string{}
	if err := readSources(tar.NewReader(reader), sources, destination, repositoryPath); err != nil {
		return nil, err
	}
	return sources, nil
}

func readSources(tr *tar.Reader, sources map[string]string, destination, repositoryPath string) error {
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Join(destination, strings.TrimPrefix(path.Clean(h.Name), "/"))
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if prohibitedSource(name) || prohibitedSource(path.Join(repositoryPath, h.Name)) {
			return fmt.Errorf("vendored path in Git sources %s", name)
		}
		if strings.HasPrefix(path.Base(name), ".wh.") {
			delete(sources, path.Join(path.Dir(name), strings.TrimPrefix(path.Base(name), ".wh.")))
			continue
		}
		if h.Typeflag == tar.TypeLink {
			source, ok := sources[path.Join(destination, strings.TrimPrefix(h.Linkname, "/"))]
			if !ok {
				return fmt.Errorf("unresolved source hardlink %s", name)
			}
			sources[name] = source
			continue
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		prefix := make([]byte, min(h.Size, 16))
		if _, err := io.ReadFull(tr, prefix); err != nil {
			return err
		}
		if binaryLike(prefix, false, name) {
			return fmt.Errorf("prebuilt binary in Git sources %s", name)
		}
		hash := sha256.New()
		if _, err := hash.Write(prefix); err != nil {
			return err
		}
		if _, err := io.Copy(hash, tr); err != nil {
			return err
		}
		sources[name] = fmt.Sprintf("sha256:%x", hash.Sum(nil))
	}
}
