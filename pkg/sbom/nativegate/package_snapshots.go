package nativegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type PackageSnapshot struct {
	Stage           string
	View            *shippedscope.ImageSnapshot
	RequiresSources bool
}

func CollectPackageSources(ctx context.Context, snapshots []PackageSnapshot, directory string, opts ReadPackageSourcesOptions) (*sources.Receipt, error) {
	if len(snapshots) == 0 {
		return nil, fmt.Errorf("no-data: no stage snapshots to establish package installations")
	}
	result := &sources.Receipt{Version: sources.Version, Sources: []sources.Source{}}
	seen := map[string]string{}
	for _, snapshot := range snapshots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if snapshot.View == nil || snapshot.View.Index == nil || snapshot.View.Index.Incomplete {
			return nil, fmt.Errorf("%s: no-data: incomplete package snapshot", snapshot.Stage)
		}
		index := snapshot.View.Index
		present := false
		for name := range index.Files {
			if packageStatePath(name) {
				present = true
			}
		}
		for name := range index.Directories {
			if packageStatePath(name) {
				present = true
			}
		}
		for name := range index.Symlinks {
			if name == "/var" || name == "/var/lib" || packageStatePath(name) {
				return nil, fmt.Errorf("%s: unsupported symlink in pm state at %s", name, snapshot.Stage)
			}
		}
		if !present {
			if snapshot.RequiresSources {
				return nil, fmt.Errorf("%s: no-data: package installation has no /var/lib/pm source state", snapshot.Stage)
			}
			continue
		}
		rootPath, err := os.MkdirTemp(directory, "pm-snapshot-")
		if err != nil {
			return nil, fmt.Errorf("create pm snapshot root: %w", err)
		}
		if err := materializePackageSnapshot(snapshot.View, rootPath); err != nil {
			return nil, err
		}
		receipt, err := ReadPackageSources(ctx, rootPath, opts)
		if err != nil {
			return nil, fmt.Errorf("%s: /var/lib/pm/sbom-sources.json: %w", snapshot.Stage, err)
		}
		for _, source := range receipt.Sources {
			identity, err := parseOriginalSourceIdentity(source)
			if err != nil {
				return nil, err
			}
			key := source.Registry + "@" + identity.Pin.String() + "\n" + source.Platform
			var packet bytes.Buffer
			if err := json.Compact(&packet, source.Packet); err != nil {
				return nil, fmt.Errorf("compact package metadata: %w", err)
			}
			if previous, exists := seen[key]; exists {
				if previous != packet.String() {
					return nil, fmt.Errorf("%s: conflicting package metadata for %s", snapshot.Stage, key)
				}
				continue
			}
			seen[key] = packet.String()
			result.Sources = append(result.Sources, source)
		}
	}
	return result, nil
}

func packageStatePath(name string) bool {
	return name == "/var/lib/pm" || strings.HasPrefix(name, "/var/lib/pm/")
}

func materializePackageSnapshot(view *shippedscope.ImageSnapshot, directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open pm snapshot root: %w", err)
	}
	defer root.Close()
	for name, file := range view.Index.Files {
		if !packageStatePath(name) {
			continue
		}
		body, exists := view.Bodies[name]
		if !exists || digest(body) != file.Digest || int64(len(body)) != file.Size {
			return fmt.Errorf("%s: no-data: package snapshot bytes missing or inconsistent", name)
		}
		if path.Clean(name) != name {
			return fmt.Errorf("invalid package snapshot path %q", name)
		}
		relative := strings.TrimPrefix(name, "/")
		if err := root.MkdirAll(path.Dir(relative), 0o700); err != nil {
			return fmt.Errorf("create package snapshot directory: %w", err)
		}
		if err := root.WriteFile(relative, body, 0o600); err != nil {
			return fmt.Errorf("write package snapshot %s: %w", name, err)
		}
	}
	return nil
}
