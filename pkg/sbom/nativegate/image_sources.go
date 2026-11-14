package nativegate

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func ImagePackageSources(ctx context.Context, img v1.Image, directory string, opts ReadPackageSourcesOptions) (*sources.Receipt, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open package state root: %w", err)
	}
	defer root.Close()
	stream := mutate.Extract(img)
	defer stream.Close()
	reader := tar.NewReader(stream)
	present := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read package state from image: %w", err)
		}
		name := strings.TrimPrefix(path.Clean("/"+header.Name), "/")
		if name != "var/lib/pm" && !strings.HasPrefix(name, "var/lib/pm/") {
			continue
		}
		present = true
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
				return nil, err
			}
			file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, fmt.Errorf("materialize package state %s: %w", name, err)
			}
			_, copyErr := io.Copy(file, reader)
			if err := errors.Join(copyErr, file.Close()); err != nil {
				return nil, fmt.Errorf("write package state %s: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("/%s: unsupported package state file type %d", name, header.Typeflag)
		}
	}
	if !present {
		return &sources.Receipt{Version: sources.Version, Sources: []sources.Source{}}, nil
	}
	return ReadPackageSources(ctx, directory, opts)
}

func ImageOriginals(ctx context.Context, bom *cdx.BOM, platform string) ([]Original, error) {
	if err := ValidateImageSource(ctx, "/", "source", bom, platform); err != nil {
		return nil, err
	}
	components := map[string]cdx.Component{}
	for _, component := range *bom.Components {
		components[component.BOMRef] = component
	}
	dependencies := map[string][]string{}
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies != nil {
				dependencies[dep.Ref] = *dep.Dependencies
			}
		}
	}
	var result []Original
	for _, file := range *bom.Components {
		if file.Type != cdx.ComponentTypeFile {
			continue
		}
		if !path.IsAbs(file.Name) || path.Clean(file.Name) != file.Name || file.Hashes == nil {
			return nil, fmt.Errorf("%s: no-data: invalid SBOM file", file.Name)
		}
		checksum := ""
		for _, hash := range *file.Hashes {
			if hash.Algorithm == cdx.HashAlgoSHA256 {
				checksum = "sha256:" + hash.Value
			}
		}
		if !digestPattern.MatchString(checksum) {
			return nil, fmt.Errorf("%s: no-data: missing SHA256 in source SBOM", file.Name)
		}
		ownerPURL, originalPath := "", ""
		if file.Properties != nil {
			for _, prop := range *file.Properties {
				if prop.Name == "dk:owner" {
					ownerPURL = prop.Value
				}
				if prop.Name == "dk:original-path" {
					originalPath = prop.Value
				}
			}
		}
		var owners []cdx.Component
		for _, ref := range dependencies[file.BOMRef] {
			component, exists := components[ref]
			if !exists {
				return nil, fmt.Errorf("%s: no-data: missing component %s", file.Name, ref)
			}
			if component.Type != cdx.ComponentTypeFile && (ownerPURL == "" || component.PackageURL == ownerPURL) {
				owners = append(owners, component)
			}
		}
		if len(owners) == 0 {
			return nil, fmt.Errorf("%s: no-data: no source component in SBOM", file.Name)
		}
		if ownerPURL != "" && len(owners) != 1 {
			return nil, fmt.Errorf("%s: ambiguous source component in SBOM", file.Name)
		}
		owner := owners[0]
		if ownerPURL == "" && len(owners) > 1 {
			if bom.Metadata.Component == nil {
				return nil, fmt.Errorf("%s: no-data: source image identity missing", file.Name)
			}
			owner = *bom.Metadata.Component
		}
		result = append(result, Original{Path: file.Name, SourcePath: originalPath, SHA256: checksum, Component: owner, Kind: "image"})
	}
	return result, nil
}
