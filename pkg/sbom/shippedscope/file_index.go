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

// IndexImageFiles records what the image ships: every regular file by rooted path, with
// the digest of its content, and every symlink with its target exactly as the image spells
// it — possibly relative, possibly dangling.
//
// A path two layers spell differently ("/a" and "a") is one entry here, holding what the
// topmost layer put there. A hardlink carries the content its own layer gives the target,
// which is what the running image sees even once an upper layer replaces or removes that
// target. A link no layer can resolve is left out and reported, so treat a path missing
// from the index as "not proven present" rather than "proven absent".
//
// Hardlinks make the layers be read a second time, so an image whose layers are expensive
// to obtain pays for that twice.
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

	remaining, err := resolveHardlinksWithinLayers(ctx, img, index, hardlinks)
	if err != nil {
		return nil, err
	}

	resolveHardlinks(ctx, index, remaining)

	return index, nil
}

// A layer tar spells a hardlink as a regular file plus a link entry beside it, so the bytes
// it names are the ones its own layer holds. Extract flattens that boundary away, and a
// lookup in the flattened index would credit the link with whatever an upper layer later
// wrote to the same path. Inflating the layers again is what this costs — measured at a
// sixth of the first pass on uncompressed layers and at nearly its equal on compressed ones,
// where the gzip dominates — so it runs only for images that hold hardlinks and stops as
// soon as every link has been answered.
func resolveHardlinksWithinLayers(ctx context.Context, img v1.Image, index *FileIndex, hardlinks map[string]string) (map[string]string, error) {
	if len(hardlinks) == 0 {
		return hardlinks, nil
	}

	targets := make(map[string]bool, len(hardlinks))
	remaining := make(map[string]string, len(hardlinks))
	for name, target := range hardlinks {
		remaining[name] = target
		targets[target] = true
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}

	settled := make(map[string]bool, len(hardlinks))
	for i := len(layers) - 1; i >= 0 && len(settled) < len(hardlinks); i-- {
		if err := resolveHardlinksInLayer(ctx, layers[i], index, remaining, targets, settled); err != nil {
			return nil, err
		}
	}

	return remaining, nil
}

func resolveHardlinksInLayer(ctx context.Context, layer v1.Layer, index *FileIndex, remaining map[string]string, targets, settled map[string]bool) error {
	contents, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("read layer contents: %w", err)
	}
	defer contents.Close()

	files := make(map[string]File)
	symlinks := make(map[string]string)
	owned := make(map[string]string)

	reader := tar.NewReader(contents)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			resolveOwnedHardlinks(index, remaining, owned, files, symlinks)

			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer contents: %w", err)
		}

		name := rootedPath(header.Name)

		switch header.Typeflag {
		case tar.TypeReg:
			if !targets[name] {
				continue
			}

			hasher := sha256.New()
			if _, err := io.Copy(hasher, reader); err != nil {
				return fmt.Errorf("hash %q: %w", name, err)
			}

			files[name] = File{
				Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
				Size:   header.Size,
			}
		case tar.TypeSymlink:
			if targets[name] {
				symlinks[name] = header.Linkname
			}
		case tar.TypeLink:
			target, ok := remaining[name]
			if !ok || settled[name] {
				continue
			}

			// The topmost layer holding the link owns it, whether or not its target is
			// there; a lower layer's answer would describe a path this one replaced.
			settled[name] = true
			owned[name] = target
		}
	}
}

// A link entry may precede the target it names, so the layer answers only once its tar has
// been read to the end.
func resolveOwnedHardlinks(index *FileIndex, remaining, owned map[string]string, files map[string]File, symlinks map[string]string) {
	for name, target := range owned {
		if file, ok := files[target]; ok {
			index.Files[name] = file
			delete(remaining, name)

			continue
		}

		if link, ok := symlinks[target]; ok {
			index.Symlinks[name] = link
			delete(index.Files, name)
			delete(remaining, name)
		}
	}
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

// Links whose own layer could not answer: the target is a symlink, another hardlink, or an
// entry a later layer whited out. The first two resolve against the flattened view, the
// third leaves content that is in the image but whose digest no layer still records.
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
				logboek.Context(ctx).Debug().LogF("hardlink %q could not be resolved to the content of %q\n", name, target)
				break
			}

			visited[target] = true
			target = next
		}
	}

	if unresolved > 0 {
		logboek.Context(ctx).Warn().LogF("WARNING: %d hardlinks could not be resolved to content and are left out of the file index\n", unresolved)
	}
}

func rootedPath(name string) string {
	return "/" + strings.TrimPrefix(path.Clean(name), "/")
}
