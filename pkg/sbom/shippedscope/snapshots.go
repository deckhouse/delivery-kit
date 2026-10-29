package shippedscope

import (
	"context"
	"fmt"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// ImageSnapshot is what the image holds at one layer boundary: the index of the prefix
// filesystem, and the bytes of the asked-for paths that boundary still carries.
type ImageSnapshot struct {
	Index *FileIndex
	// Bodies holds, by rooted path, the content of the captured paths present at this
	// boundary; a path the boundary does not hold is simply absent.
	Bodies map[string][]byte
}

type CollectImageSnapshotsOptions struct {
	// CapturePaths names the rooted paths whose bytes travel with every snapshot. No other
	// content is retained, so a consumer that needs a file must name it here.
	CapturePaths []string
}

// CollectImageSnapshots reads the image at the given layer boundaries — a boundary of n
// being the filesystem the first n layers make, so 0 is the empty one — and answers what
// each of them holds. The boundaries are the caller's, drawn from stage layer counts, and
// diffIDs is the layer chain those counts were drawn from: both are checked against the
// image before anything is read, so a snapshot never describes a different image than the
// one the boundaries came from.
//
// A boundary whose index needs hardlink fallback is an error rather than a snapshot: such
// an index cannot establish that a path is absent, which is the question a snapshot of an
// earlier boundary exists to answer. Nothing partial comes back; any failure fails the call.
func CollectImageSnapshots(ctx context.Context, img v1.Image, diffIDs []v1.Hash, boundaries []int, opts CollectImageSnapshotsOptions) (map[int]*ImageSnapshot, error) {
	config, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("read image config: empty config")
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}
	if len(config.RootFS.DiffIDs) != len(layers) {
		return nil, fmt.Errorf("image config declares %d layers while the image holds %d", len(config.RootFS.DiffIDs), len(layers))
	}
	if !slices.Equal(config.RootFS.DiffIDs, diffIDs) {
		return nil, fmt.Errorf("image layers do not match the %d expected stage layers", len(diffIDs))
	}

	captured := make(map[string]bool, len(opts.CapturePaths))
	for _, capturePath := range opts.CapturePaths {
		if !strings.HasPrefix(capturePath, "/") {
			return nil, fmt.Errorf("capture path %q is not rooted", capturePath)
		}
		captured[rootedPath(capturePath)] = true
	}
	capture := func(file string) bool { return captured[file] }

	for _, boundary := range boundaries {
		if boundary < 0 || boundary > len(layers) {
			return nil, fmt.Errorf("invalid layer boundary %d for image with %d layers", boundary, len(layers))
		}
	}

	snapshots := make(map[int]*ImageSnapshot, len(boundaries))
	for _, boundary := range boundaries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := snapshots[boundary]; ok {
			continue
		}

		snapshot, err := collectImageSnapshot(ctx, layers[:boundary], capture)
		if err != nil {
			return nil, fmt.Errorf("read stage filesystem boundary %d: %w", boundary, err)
		}
		if snapshot.Index.Incomplete {
			return nil, fmt.Errorf("stage filesystem boundary %d needs hardlink fallback, so it cannot establish what the stage held", boundary)
		}

		snapshots[boundary] = snapshot
	}

	return snapshots, nil
}

func collectImageSnapshot(ctx context.Context, layers []v1.Layer, capture func(file string) bool) (*ImageSnapshot, error) {
	prefix, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return nil, fmt.Errorf("reconstruct filesystem: %w", err)
	}

	index, bodies, err := indexImageFiles(ctx, prefix, capture)
	if err != nil {
		return nil, err
	}

	return &ImageSnapshot{Index: index, Bodies: bodies}, nil
}
