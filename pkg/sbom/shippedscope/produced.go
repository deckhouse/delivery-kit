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
	"os"
	"slices"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/werf/werf/v3/pkg/tmp_manager"
)

// ProducedLayerRange identifies the layers appended by one eligible stage. Start is
// inclusive and End exclusive; stage boundaries must be verified against image DiffIDs.
type ProducedLayerRange struct {
	Start int
	End   int
}

type ProducedLayers struct {
	Known  bool
	Ranges []ProducedLayerRange
}

type ProducedFile struct {
	Path           string
	Digest         string
	Classification BinaryClassification
}

// ProducedFiles binds classifications to surviving binary content. Known is false when
// stage attribution or filesystem reconstruction cannot establish a complete set.
type ProducedFiles struct {
	Known bool
	Files []ProducedFile
}

// CollectProducedFiles compares each verified stage's filesystem boundaries and records
// the binary content still present in the final image, including relocated hardlinks.
func CollectProducedFiles(ctx context.Context, img v1.Image, index *FileIndex, layers ProducedLayers) (*ProducedFiles, error) {
	if !layers.Known || index.Incomplete {
		return &ProducedFiles{}, nil
	}
	imgLayers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}
	for _, r := range layers.Ranges {
		if r.Start < 0 || r.Start > r.End || r.End > len(imgLayers) {
			return nil, fmt.Errorf("invalid layer range [%d,%d) for image with %d layers", r.Start, r.End, len(imgLayers))
		}
	}

	indexes := map[int]*FileIndex{0: {Files: map[string]File{}, Symlinks: map[string]string{}}, len(imgLayers): index}
	finalDigests := indexByDigest(index)
	candidates := make(map[string]string)
	for _, r := range layers.Ranges {
		if r.Start == r.End {
			continue
		}
		for _, boundary := range []int{r.Start, r.End} {
			if _, ok := indexes[boundary]; ok {
				continue
			}
			prefix, err := mutate.AppendLayers(empty.Image, imgLayers[:boundary]...)
			if err != nil {
				return nil, fmt.Errorf("read stage filesystem boundary %d: %w", boundary, err)
			}
			boundaryIndex, err := IndexImageFiles(ctx, prefix)
			if err != nil {
				return nil, fmt.Errorf("index stage filesystem boundary %d: %w", boundary, err)
			}
			indexes[boundary] = boundaryIndex
		}
		before, after := indexes[r.Start], indexes[r.End]
		if before.Incomplete || after.Incomplete {
			return &ProducedFiles{}, nil
		}
		for path, file := range after.Files {
			if previous, ok := before.Files[path]; ok && previous.Digest == file.Digest {
				continue
			}
			paths := finalDigests[file.Digest]
			if len(paths) == 0 {
				continue
			}
			candidates[file.Digest] = slices.Min(paths)
		}
	}
	result := &ProducedFiles{Known: true}
	if len(candidates) == 0 {
		return result, nil
	}

	found := make(map[string]ProducedFile)
	for _, layer := range imgLayers {
		files, err := classifyProducedLayer(ctx, layer, candidates)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			found[file.Digest] = file
		}
	}
	for _, file := range found {
		result.Files = append(result.Files, file)
	}
	slices.SortFunc(result.Files, func(a, b ProducedFile) int { return bytes.Compare([]byte(a.Path), []byte(b.Path)) })
	return result, nil
}

func classifyProducedLayer(ctx context.Context, layer v1.Layer, candidates map[string]string) ([]ProducedFile, error) {
	contents, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("open produced image layer: %w", err)
	}
	defer contents.Close()
	reader := tar.NewReader(contents)
	var files []ProducedFile
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read produced image layer: %w", err)
		}
		if header.Typeflag != tar.TypeReg || header.Size == 0 {
			continue
		}
		prefix := make([]byte, 4)
		n, err := io.ReadFull(reader, prefix)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read produced binary header: %w", err)
		}
		_, executable, err := formatOf(bytes.NewReader(prefix[:n]))
		if err != nil {
			return nil, err
		}
		if !executable {
			continue
		}
		file, err := classifyProducedContent(ctx, io.MultiReader(bytes.NewReader(prefix[:n]), reader), header.Size, candidates)
		if err != nil {
			return nil, err
		}
		if file.Digest != "" {
			files = append(files, file)
		}
	}
	if _, err := io.Copy(io.Discard, contents); err != nil {
		return nil, fmt.Errorf("finish produced image layer: %w", err)
	}
	return files, nil
}

func classifyProducedContent(ctx context.Context, reader io.Reader, size int64, candidates map[string]string) (ProducedFile, error) {
	tmp, err := tmp_manager.TempFile("werf-sbom-produced-*.bin")
	if err != nil {
		return ProducedFile{}, fmt.Errorf("create produced binary spool: %w", err)
	}
	file, classifyErr := func() (ProducedFile, error) {
		hash := sha256.New()
		if _, err := io.Copy(io.MultiWriter(tmp, hash), reader); err != nil {
			return ProducedFile{}, fmt.Errorf("spool produced binary: %w", err)
		}
		digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		path, ok := candidates[digest]
		if !ok {
			return ProducedFile{}, nil
		}
		classification, err := ClassifyBinary(ctx, tmp, size)
		if err != nil {
			return ProducedFile{}, fmt.Errorf("classify produced binary: %w", err)
		}
		if classification.TestBinary || classification.Go == VerdictNone && classification.Rust == VerdictNone {
			return ProducedFile{}, nil
		}
		return ProducedFile{Path: path, Digest: digest, Classification: classification}, nil
	}()
	if err := errors.Join(classifyErr, tmp.Close(), os.Remove(tmp.Name())); err != nil {
		return ProducedFile{}, fmt.Errorf("read produced binary content: %w", err)
	}
	return file, nil
}
