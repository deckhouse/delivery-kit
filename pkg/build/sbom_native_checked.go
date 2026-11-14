package build

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	buildimage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func (phase *BuildPhase) nativeCheckedExport(ctx context.Context, img *buildimage.Image, saved v1.Image, paths []string) (*cdx.BOM, error) {
	if img == nil || !nativeChecked(img.GetName()) {
		return nil, fmt.Errorf("no-data: checked producer is not configured")
	}
	if err := validateNativeBootstrap(img); err != nil {
		return nil, err
	}
	desc := img.GetLastNonEmptyStageDesc()
	packages, err := phase.nativePackages(ctx, img, saved, desc)
	if err != nil {
		return nil, err
	}
	imports, err := phase.nativeImportOriginals(ctx, img, saved, desc)
	if err != nil {
		return nil, err
	}
	gitOriginals, gitLinks, err := nativeGitOriginals(ctx, img)
	if err != nil {
		return nil, err
	}
	config, err := saved.ConfigFile()
	if err != nil {
		return nil, err
	}
	roots, err := nativeUserRoots(ctx, img, config)
	if err != nil {
		return nil, err
	}
	opts := nativegate.VerifyOptions{Subject: img.GetName(), Platform: img.TargetPlatform, UserRoots: roots, ProducedFiles: packages.ProducedFiles, ProducedSymlinks: packages.ProducedSymlinks, BuildGitSources: packages.BuildGitSources, Originals: packages.Originals, TrustedComponents: packages.Components, ExpectedSymlinks: maps.Clone(packages.Symlinks)}
	opts.Originals = append(opts.Originals, imports.Originals...)
	opts.ServiceFiles = append(slices.Clone(packages.ServiceFiles), imports.ServiceFiles...)
	opts.Originals = append(opts.Originals, gitOriginals...)
	opts.TrustedComponents = append(opts.TrustedComponents, imports.Components...)
	if opts.ExpectedSymlinks == nil {
		opts.ExpectedSymlinks = map[string]string{}
	}
	maps.Copy(opts.ExpectedSymlinks, imports.Symlinks)
	maps.Copy(opts.ExpectedSymlinks, gitLinks)
	bom := cyclonedxutil.NewBOM()
	restoreImageMetadata(bom, desc)
	if err := nativegate.VerifyExport(ctx, saved, bom, paths, opts); err != nil {
		return nil, fmt.Errorf("verify export from checked image %s: %w", img.GetName(), err)
	}
	return bom, nil
}

func nativeProducedEntries(ctx context.Context, provenance sbomStageProvenance, views map[int]*shippedscope.ImageSnapshot) (map[string]string, map[string]string, error) {
	produced := map[string]string{}
	links := map[string]string{}
	var previous *shippedscope.FileIndex
	for _, snapshot := range provenance.Snapshots {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		view := views[snapshot.LayerCount]
		if view == nil || view.Index == nil || view.Index.Incomplete {
			return nil, nil, fmt.Errorf("%s: no-data: incomplete producer snapshot", snapshot.Stage)
		}
		index := view.Index
		maps.DeleteFunc(produced, func(name, digest string) bool { return index.Files[name].Digest != digest })
		maps.DeleteFunc(links, func(name, target string) bool { return index.Symlinks[name] != target })
		if previous != nil && (slices.Contains(jsObserverStageNames, snapshot.Stage) || snapshot.Stage == stage.Sign || snapshot.Stage == stage.VerityAnnotation) {
			for name, file := range index.Files {
				if prior, exists := previous.Files[name]; !exists || prior.Digest != file.Digest {
					produced[name] = file.Digest
				}
			}
			for name, target := range index.Symlinks {
				if prior, exists := previous.Symlinks[name]; !exists || prior != target {
					links[name] = target
				}
			}
		}
		previous = index
	}
	return produced, links, nil
}

func nativeCheckedPackageSnapshots(snapshots []nativegate.PackageSnapshot) ([]nativegate.PackageSnapshot, error) {
	if len(snapshots) == 0 || snapshots[0].Stage != string(stage.From) {
		return nil, fmt.Errorf("no-data: checked producer has no stock baseline")
	}
	result := slices.Clone(snapshots)
	var baseline map[string]string
	for i, snapshot := range snapshots {
		if snapshot.View == nil || snapshot.View.Index == nil || snapshot.View.Index.Incomplete {
			return nil, fmt.Errorf("%s: no-data: incomplete checked package snapshot", snapshot.Stage)
		}
		for name := range snapshot.View.Index.Symlinks {
			if name == "/var" || name == "/var/lib" || nativePackageStatePath(name) {
				return nil, fmt.Errorf("%s: unsupported symlink in checked pm state at %s", name, snapshot.Stage)
			}
		}
		state := nativePackageState(snapshot.View.Index)
		if i == 0 {
			baseline = state
		}
		if snapshot.RequiresSources || !maps.Equal(baseline, state) {
			continue
		}
		result[i].View = &shippedscope.ImageSnapshot{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Directories: map[string]struct{}{}, Symlinks: map[string]string{}}, Bodies: map[string][]byte{}}
	}
	return result, nil
}

func nativePackageState(index *shippedscope.FileIndex) map[string]string {
	state := map[string]string{}
	for name, file := range index.Files {
		if nativePackageStatePath(name) {
			state["file:"+name] = file.Digest + ":" + strconv.FormatInt(file.Size, 10)
		}
	}
	for name := range index.Directories {
		if nativePackageStatePath(name) {
			state["dir:"+name] = ""
		}
	}
	for name, target := range index.Symlinks {
		if name == "/var" || name == "/var/lib" || nativePackageStatePath(name) {
			state["link:"+name] = target
		}
	}
	return state
}

func nativePackageStatePath(name string) bool {
	return name == "/var/lib/pm" || strings.HasPrefix(name, "/var/lib/pm/")
}
