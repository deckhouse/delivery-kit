package build

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type sbomSourceSnapshot struct {
	Stage         stage.StageName
	LayerCount    int
	Index         *shippedscope.FileIndex
	Receipt       *sources.Receipt
	ReceiptStatus string
	ImportBackend string
}

func collectSBOMSourceSnapshots(ctx context.Context, img v1.Image, provenance sbomStageProvenance) ([]sbomSourceSnapshot, error) {
	if !provenance.Layers.Known || len(provenance.Snapshots) == 0 {
		return nil, fmt.Errorf("no-data: source snapshot boundaries are unknown")
	}
	if provenance.Snapshots[0].Stage != stage.From || provenance.Snapshots[len(provenance.Snapshots)-1].LayerCount != len(provenance.DiffIDs) {
		return nil, fmt.Errorf("invalid: source snapshots do not cover the image stage chain")
	}
	boundaries := make([]int, 0, len(provenance.Snapshots))
	previous := 0
	for _, snapshot := range provenance.Snapshots {
		if snapshot.LayerCount < previous {
			return nil, fmt.Errorf("invalid: source snapshot boundaries are not ordered")
		}
		boundaries = append(boundaries, snapshot.LayerCount)
		previous = snapshot.LayerCount
	}
	views, err := shippedscope.CollectImageSnapshots(ctx, img, provenance.DiffIDs, boundaries, shippedscope.CollectImageSnapshotsOptions{CapturePaths: []string{sources.DefaultPath}})
	if err != nil {
		return nil, fmt.Errorf("capture source snapshots: %w", err)
	}
	result := make([]sbomSourceSnapshot, 0, len(provenance.Snapshots))
	for _, snapshot := range provenance.Snapshots {
		view := views[snapshot.LayerCount]
		if _, ok := view.Index.Symlinks[sources.DefaultPath]; ok {
			return nil, fmt.Errorf("stage %s: invalid: source receipt %s is a symlink", snapshot.Stage, sources.DefaultPath)
		}
		entry := sbomSourceSnapshot{Stage: snapshot.Stage, LayerCount: snapshot.LayerCount, ImportBackend: snapshot.ImportBackend, Index: view.Index, ReceiptStatus: "no-data"}
		receipt, status, err := parseSourceReceipt(view)
		if err != nil {
			return nil, fmt.Errorf("stage %s: %s: read source receipt %s: %w", snapshot.Stage, status, sources.DefaultPath, err)
		}
		if receipt != nil {
			entry.Receipt, entry.ReceiptStatus = receipt, status
		}
		result = append(result, entry)
	}
	return result, nil
}

func parseSourceReceipt(view *shippedscope.ImageSnapshot) (*sources.Receipt, string, error) {
	// A deleted receipt is an absent one; a directory holding its reserved path is not.
	if _, reserved := view.Index.Directories[sources.DefaultPath]; reserved {
		return nil, "invalid", fmt.Errorf("source receipt %s is a directory", sources.DefaultPath)
	}
	body, exists := view.Bodies[sources.DefaultPath]
	if !exists {
		return nil, "no-data", nil
	}
	receipt, status, err := sources.Parse(body)
	if status != "present" {
		if err == nil {
			err = fmt.Errorf("source receipt is empty")
		}
		return nil, status, err
	}
	return receipt, status, nil
}

// sbomSourceImportInput is one import directive of the built image as the build applies
// it: the stage boundary it lands on, the pinned source image it copies from, and the
// scope of the copy. The source reference is empty when the build could not pin the
// source image to a digest, which the native gate refuses rather than guesses.
type sbomSourceImportInput struct {
	Stage     stage.StageName
	Reference string
	BOM       *cdx.BOM
	Scope     nativegate.ImportScope
	// Bootstrap marks a source whose own composition this project does not describe.
	// Nothing it says about itself is read, and every file taken out of it has to be
	// accounted for by this image or counted as unknown.
	Bootstrap bool
	// Originals are the prepared sources this recipe declares the files of that
	// bootstrap source to come from.
	Originals []nativegate.ImportOriginal
	// Packages are the prepared sources the bootstrap source image's own recipe
	// declares its stages compile, which a mapping may name beside the ones its pm
	// receipt pins.
	Packages []sources.Source
}

func sbomSourceImportsChecksum(inputs []sbomSourceImportInput) string {
	parts := make([]string, 0, len(inputs)*8)
	for i, input := range inputs {
		parts = append(parts,
			strconv.Itoa(i), string(input.Stage), input.Reference,
			string(input.Scope.Backend),
			input.Scope.FromPath, input.Scope.ToPath,
			strings.Join(input.Scope.IncludePaths, "///"),
			strings.Join(input.Scope.ExcludePaths, "///"),
			strconv.FormatBool(input.Bootstrap),
		)
		parts = append(parts, sbomBootstrapOriginalsChecksum(input.Originals)...)
		parts = append(parts, sbomBootstrapPackagesChecksum(input.Packages)...)
	}

	return util.Sha256Hash(parts...)
}

// sourceImagePuller is what reading an import source image needs: the backend places the
// image locally, then it is read out as a tarball the way the built image is.
type sourceImagePuller interface {
	imageSaver
	Pull(ctx context.Context, ref string, opts container_backend.PullOpts) error
}

type sbomSourceImage struct {
	Index   *shippedscope.FileIndex
	Receipt *sources.Receipt
	Bodies  map[string][]byte
	// Database is what this image's own distribution records about itself, read from
	// the same capture: the one first-hand answer to what the packages of its document
	// consist of and where they stand.
	Database *shippedscope.DistroDatabase
}

// captureSBOMSourceImages reads every image the imports copy from, once per pinned
// reference. The image is read as its own final filesystem — what the import sees — and
// the package source receipt it carries comes from the same capture.
//
// A source already read while its document was being scoped is taken from alreadyRead
// rather than read again: it is the same image at the same digest, and the capture asks
// it the same questions.
func captureSBOMSourceImages(ctx context.Context, backend sourceImagePuller, inputs []sbomSourceImportInput, targetPlatform string, alreadyRead map[string]*sbomSourceImage) (map[string]*sbomSourceImage, error) {
	captured := make(map[string]*sbomSourceImage, len(alreadyRead))
	maps.Copy(captured, alreadyRead)
	for _, input := range inputs {
		if input.Reference == "" {
			return nil, fmt.Errorf("no-data: import source of stage %s is not pinned to a digest", input.Stage)
		}
		if _, exists := captured[input.Reference]; exists {
			continue
		}
		source, err := captureSBOMSourceImage(ctx, backend, input.Reference, targetPlatform)
		if err != nil {
			return nil, err
		}
		captured[input.Reference] = source
	}

	return captured, nil
}

func captureSBOMSourceImage(ctx context.Context, backend sourceImagePuller, reference, targetPlatform string) (*sbomSourceImage, error) {
	return captureSBOMSourceImagePaths(ctx, backend, reference, targetPlatform, []string{sources.DefaultPath})
}

func captureSBOMSourceImagePaths(ctx context.Context, backend sourceImagePuller, reference, targetPlatform string, paths []string) (*sbomSourceImage, error) {
	if err := backend.Pull(ctx, reference, container_backend.PullOpts{TargetPlatform: targetPlatform}); err != nil {
		return nil, fmt.Errorf("pull import source %s: %w", reference, err)
	}
	img, cleanup, err := savedImage(ctx, backend, reference)
	if err != nil {
		return nil, fmt.Errorf("read import source %s: %w", reference, err)
	}
	defer cleanup()

	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read import source %s config: %w", reference, err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("read import source %s config: empty config", reference)
	}
	boundary := len(cfg.RootFS.DiffIDs)
	views, err := shippedscope.CollectImageSnapshots(ctx, img, cfg.RootFS.DiffIDs, []int{boundary}, shippedscope.CollectImageSnapshotsOptions{
		CapturePaths: paths,
		// The package database of the source travels with the same reading: what its
		// document claims about its own packages is answered from it, and walking the
		// image a second time would answer the same.
		//
		// It travels with every reading and not only with the ones that go on to ask
		// the question. A reading that answered some questions about an image and not
		// others would be a trap for whoever held it next, and what this adds is the
		// file lists of the source's own packages and nothing else.
		CaptureMatch: shippedscope.IsDistroPackageDatabase,
	})
	if err != nil {
		return nil, fmt.Errorf("capture import source %s: %w", reference, err)
	}
	view := views[boundary]
	if _, ok := view.Index.Symlinks[sources.DefaultPath]; ok {
		return nil, fmt.Errorf("import source %s: invalid: source receipt %s is a symlink", reference, sources.DefaultPath)
	}
	receipt, status, err := parseSourceReceipt(view)
	if err != nil {
		return nil, fmt.Errorf("import source %s: %s: read source receipt %s: %w", reference, status, sources.DefaultPath, err)
	}

	return &sbomSourceImage{
		Index: view.Index, Receipt: receipt, Bodies: view.Bodies,
		Database: shippedscope.DistroPackagesFrom(view.Index, view.Bodies),
	}, nil
}

// sbomSourceGateSnapshots hands the captured stage boundaries to the native gate with the
// imports of the build attached, in build order, to the boundary each one lands on. An
// import whose stage the built image does not hold is unplaceable evidence, not an import
// to drop.
func sbomSourceGateSnapshots(snapshots []sbomSourceSnapshot, inputs []sbomSourceImportInput, captured map[string]*sbomSourceImage) ([]nativegate.SourceSnapshot, error) {
	result := make([]nativegate.SourceSnapshot, 0, len(snapshots))
	position := make(map[stage.StageName]int, len(snapshots))
	for _, snapshot := range snapshots {
		position[snapshot.Stage] = len(result)
		result = append(result, nativegate.SourceSnapshot{
			Stage:   string(snapshot.Stage),
			Index:   snapshot.Index,
			Receipt: snapshot.Receipt,
		})
	}

	for _, input := range inputs {
		if input.Scope.FromPath == "" || input.Scope.ToPath == "" {
			return nil, fmt.Errorf("no-data: import of stage %s carries no copy scope", input.Stage)
		}
		at, known := position[input.Stage]
		if !known {
			return nil, fmt.Errorf("no-data: stage %s of an import is not a boundary of the built image", input.Stage)
		}
		source, exists := captured[input.Reference]
		if !exists {
			return nil, fmt.Errorf("no-data: import source %s of stage %s was not read", input.Reference, input.Stage)
		}
		scope := input.Scope
		switch snapshots[at].ImportBackend {
		case "copy-recurse":
			scope.Backend = nativegate.ImportBackendCopyRecurse
		case "rsync":
			scope.Backend = nativegate.ImportBackendRsync
		default:
			return nil, fmt.Errorf("no-data: import backend of stage %s is unknown", input.Stage)
		}
		result[at].Imports = append(result[at].Imports, nativegate.SourceImport{
			Index:     source.Index,
			BOM:       input.BOM,
			Receipt:   source.Receipt,
			Scope:     scope,
			Bootstrap: input.Bootstrap,
			Originals: input.Originals,
			Packages:  input.Packages,
		})
	}

	return result, nil
}
