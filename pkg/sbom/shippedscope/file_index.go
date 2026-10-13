package shippedscope

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/werf/logboek"
)

type File struct {
	// Digest is "sha256:<hex>", the form /var/lib/pm/files.json and SBOM occurrences use.
	Digest string
	Size   int64
}

type FileIndex struct {
	Files map[string]File
	// Symlinks holds targets exactly as the image records them: possibly relative, possibly dangling.
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read image filesystem: %w", err)
		}

		name := rootedPath(header.Name)
		if indexed(index, hardlinks, name) {
			continue
		}

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

	// A failure inside Extract closes its pipe with the error, but the tar trailer it
	// has already written makes the reader above stop at io.EOF first. Without this
	// drain a rejected path or a layer whose digest does not verify would silently
	// yield a partial index instead of an error.
	if _, err := io.Copy(io.Discard, rootfs); err != nil {
		return nil, fmt.Errorf("read image filesystem: %w", err)
	}

	resolveHardlinks(ctx, index, hardlinks)

	return index, nil
}

// Extract emits the topmost layer first, so the first entry seen for a path is the one
// that layering leaves in place. Paths spelled differently in different layers ("/a" and
// "a") collapse to one key here, where upstream keeps them apart.
func indexed(index *FileIndex, hardlinks map[string]string, name string) bool {
	if _, ok := index.Files[name]; ok {
		return true
	}
	if _, ok := index.Symlinks[name]; ok {
		return true
	}
	_, ok := hardlinks[name]

	return ok
}

// A hardlink carries no content of its own and may precede its target, point at another
// hardlink, or outlive a target a later layer whited out. The first two are resolved here;
// the third leaves content that is in the image but whose digest it no longer records.
func resolveHardlinks(ctx context.Context, index *FileIndex, hardlinks map[string]string) {
	var unresolved int

	for _, name := range slices.Sorted(maps.Keys(hardlinks)) {
		target := hardlinks[name]
		visited := map[string]bool{name: true}

		for {
			if file, ok := index.Files[target]; ok {
				index.Files[name] = file
				break
			}
			if link, ok := index.Symlinks[target]; ok {
				index.Symlinks[name] = link
				break
			}

			next, ok := hardlinks[target]
			if !ok || visited[target] {
				unresolved++
				logboek.Context(ctx).Debug().LogF("hardlink %q points to %q, which the image filesystem does not contain\n", name, target)
				break
			}

			visited[target] = true
			target = next
		}
	}

	if unresolved > 0 {
		logboek.Context(ctx).Warn().LogF("WARNING: %d hardlinks point outside the image filesystem and are left out of the file index\n", unresolved)
	}
}

func rootedPath(name string) string {
	return "/" + strings.TrimPrefix(path.Clean(name), "/")
}
