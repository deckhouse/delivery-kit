package nativegate

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"strings"
)

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
