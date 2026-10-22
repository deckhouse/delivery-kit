package shippedscope

import (
	"archive/tar"
	"bytes"
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
	// Incomplete also covers hardlinks resolved against the final filesystem rather
	// than their owning layer: later target changes may have hidden surviving bytes.
	// Such an index cannot establish that a digest is absent.
	Incomplete bool

	// bodies holds the captured content by indexed name; targetBodies holds, by target
	// path, the content a hardlink's name asked for while the layers were read.
	bodies       map[string][]byte
	targetBodies map[string][]byte
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
	index, _, err := indexImageFiles(ctx, img, nil)

	return index, err
}

// capture names the files whose bytes the caller needs beside their digest; they are read
// once, while the file passes by, instead of costing another walk of the image. The bytes
// travel with the entry, so a hardlink to such a file gets them along with its digest. A
// symlink to one does not: it stays a symlink in the index, as everywhere else.
func indexImageFiles(ctx context.Context, img v1.Image, capture func(path string) bool) (*FileIndex, map[string][]byte, error) {
	index := &FileIndex{
		Files:        make(map[string]File),
		Symlinks:     make(map[string]string),
		bodies:       make(map[string][]byte),
		targetBodies: make(map[string][]byte),
	}
	hardlinks := make(map[string]string)
	if capture == nil {
		capture = func(string) bool { return false }
	}

	rootfs := mutate.Extract(img)
	defer rootfs.Close()

	reader := tar.NewReader(rootfs)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read image filesystem: %w", err)
		}

		name := rootedPath(header.Name)
		if indexed(index, hardlinks, name) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeReg:
			file, body, err := readFile(reader, header, capture(name))
			if err != nil {
				return nil, nil, fmt.Errorf("hash %q: %w", name, err)
			}

			index.Files[name] = file
			if body != nil {
				index.bodies[name] = body
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
		return nil, nil, fmt.Errorf("read image filesystem: %w", err)
	}

	remaining, err := resolveHardlinksWithinLayers(ctx, img, index, hardlinks, capture)
	if err != nil {
		return nil, nil, err
	}

	if len(remaining) > 0 {
		index.Incomplete = true
	}
	resolveHardlinks(ctx, index, remaining)

	captured := index.bodies
	index.bodies = nil
	index.targetBodies = nil

	return index, captured, nil
}

// The body is nil unless kept; a kept body is never nil, however short the file.
func readFile(reader io.Reader, header *tar.Header, keepBody bool) (File, []byte, error) {
	hasher := sha256.New()

	var body bytes.Buffer
	var sink io.Writer = hasher
	if keepBody {
		sink = io.MultiWriter(hasher, &body)
	}

	if _, err := io.Copy(sink, reader); err != nil {
		return File{}, nil, err
	}

	file := File{
		Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		Size:   header.Size,
	}
	if !keepBody {
		return file, nil, nil
	}

	return file, append([]byte{}, body.Bytes()...), nil
}

// A layer tar spells a hardlink as a regular file plus a link entry beside it, so the bytes
// it names are the ones its own layer holds. Extract flattens that boundary away, and a
// lookup in the flattened index would credit the link with whatever an upper layer later
// wrote to the same path. Inflating the layers again is what this costs — measured at a
// sixth of the first pass on uncompressed layers and at nearly its equal on compressed ones,
// where the gzip dominates — so it runs only for images that hold hardlinks and stops as
// soon as every link has been answered.
func resolveHardlinksWithinLayers(ctx context.Context, img v1.Image, index *FileIndex, hardlinks map[string]string, capture func(path string) bool) (map[string]string, error) {
	if len(hardlinks) == 0 {
		return hardlinks, nil
	}

	// A target is read for the link's sake, so it is the link's name that decides whether
	// the bytes are kept.
	targets := make(map[string]bool, len(hardlinks))
	remaining := make(map[string]string, len(hardlinks))
	for name, target := range hardlinks {
		remaining[name] = target
		keepBody := capture(name)
		for !targets[target] {
			targets[target] = keepBody
			if !keepBody {
				break
			}
			next, ok := hardlinks[target]
			if !ok {
				break
			}
			target = next
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}

	settled := make(map[string]bool, len(hardlinks))
	for i := len(layers) - 1; i >= 0; i-- {
		if len(settled) == len(hardlinks) && !bodyOwed(index, remaining, capture) {
			break
		}

		if err := resolveHardlinksInLayer(ctx, layers[i], index, remaining, targets, settled); err != nil {
			return nil, err
		}
	}

	return remaining, nil
}

// A link its own layer could not answer is resolved against the flattened view later, and
// the bytes its name asked for have to come from the layer that holds the target.
func bodyOwed(index *FileIndex, remaining map[string]string, capture func(path string) bool) bool {
	for name, target := range remaining {
		if !capture(name) {
			continue
		}

		if _, ok := index.targetBodies[target]; !ok {
			return true
		}
	}

	return false
}

func resolveHardlinksInLayer(ctx context.Context, layer v1.Layer, index *FileIndex, remaining map[string]string, targets, settled map[string]bool) error {
	contents, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("read layer contents: %w", err)
	}
	defer contents.Close()

	files := make(map[string]File)
	bodies := make(map[string][]byte)
	symlinks := make(map[string]string)
	owned := make(map[string]string)

	reader := tar.NewReader(contents)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			resolveOwnedHardlinks(index, remaining, owned, files, bodies, symlinks)

			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer contents: %w", err)
		}

		name := rootedPath(header.Name)

		switch header.Typeflag {
		case tar.TypeReg:
			keepBody, ok := targets[name]
			if !ok {
				continue
			}

			file, body, err := readFile(reader, header, keepBody)
			if err != nil {
				return fmt.Errorf("hash %q: %w", name, err)
			}

			files[name] = file
			if body != nil {
				bodies[name] = body
				if _, ok := index.targetBodies[name]; !ok {
					index.targetBodies[name] = body
				}
			}
		case tar.TypeSymlink:
			if _, ok := targets[name]; ok {
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
func resolveOwnedHardlinks(index *FileIndex, remaining, owned map[string]string, files map[string]File, bodies map[string][]byte, symlinks map[string]string) {
	for name, target := range owned {
		visited := map[string]bool{name: true}
		for {
			if file, ok := files[target]; ok {
				index.Files[name] = file
				files[name] = file
				if body, ok := bodies[target]; ok {
					index.bodies[name] = body
					bodies[name] = body
				}
				delete(remaining, name)
				break
			}
			if link, ok := symlinks[target]; ok {
				index.Symlinks[name] = link
				symlinks[name] = link
				delete(remaining, name)
				break
			}
			next, ok := owned[target]
			if !ok || visited[target] {
				break
			}
			visited[target] = true
			target = next
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

// Links whose own layer could not answer: the target lives in another layer, or is another
// hardlink. Both resolve against the flattened view, which is as close as the image gets to
// an answer once the layer that owns the link does not hold the target.
func resolveHardlinks(ctx context.Context, index *FileIndex, hardlinks map[string]string) {
	var unresolved int

	for _, name := range slices.Sorted(maps.Keys(hardlinks)) {
		target := hardlinks[name]
		visited := map[string]bool{name: true}

		for {
			if file, ok := index.Files[target]; ok {
				index.Files[name] = file
				if body, ok := index.targetBodies[target]; ok {
					index.bodies[name] = body
				}
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
		index.Incomplete = true
		logboek.Context(ctx).Warn().LogF("WARNING: %d hardlinks could not be resolved to content and are left out of the file index\n", unresolved)
	}
}

func rootedPath(name string) string {
	return "/" + strings.TrimPrefix(path.Clean(name), "/")
}
