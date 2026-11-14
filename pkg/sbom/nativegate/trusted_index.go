package nativegate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"regexp"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	osPm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

func LoadTrustedIndexes(ctx context.Context, references []string, platform string) (map[string]bool, error) {
	result := map[string]bool{}
	for _, reference := range references {
		ref, err := name.NewDigest(reference, name.StrictValidation)
		if err != nil || ref.Name() != reference {
			return nil, fmt.Errorf("trusted index must be a canonical pinned repo@digest: %q", reference)
		}
		pin, err := v1.NewHash(ref.DigestStr())
		if err != nil {
			return nil, fmt.Errorf("parse trusted index digest: %w", err)
		}
		target, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, fmt.Errorf("parse trusted index platform: %w", err)
		}
		img, _, err := verifiedOriginalImage(ctx, ref.Context(), pin, *target)
		if err != nil {
			return nil, err
		}
		packages, err := trustedIndexPackages(ctx, ref.Context().Name(), img)
		if err != nil {
			return nil, fmt.Errorf("trusted index %s: %w", reference, err)
		}
		maps.Copy(result, packages)
	}
	return result, nil
}

func trustedIndexPackages(ctx context.Context, repository string, img v1.Image) (map[string]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest: %w", err)
	}
	if manifest.Annotations["io.deckhouse.sbom.instrumented"] != "v1" || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(manifest.Annotations["io.deckhouse.sbom.base-images-revision"]) {
		return nil, fmt.Errorf("index has no instrumented v1 marker and revision")
	}
	registry, ok := strings.CutSuffix(repository, "/index")
	if !ok {
		return nil, fmt.Errorf("pm index repository must end in /index: %s", repository)
	}
	view, err := original.NewOriginalPackage(img)
	if err != nil {
		return nil, fmt.Errorf("read index filesystem: %w", err)
	}
	reader, err := view.Open("index.json")
	if err != nil {
		return nil, fmt.Errorf("open index.json: %w", err)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read index.json: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close index.json: %w", closeErr)
	}
	var packages []osPm.PmPackageInfo
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	if packages == nil {
		return nil, fmt.Errorf("no-data: index.json has no package list")
	}
	result := map[string]bool{}
	for _, pkg := range packages {
		if pkg.Name == "" || pkg.Version == "" || len(pkg.Arch) == 0 || !digestPattern.MatchString(pkg.Digest) {
			return nil, fmt.Errorf("index.json: incomplete package %s", pkg.Name)
		}
		result[registry+"@"+pkg.Digest] = true
	}
	return result, nil
}
