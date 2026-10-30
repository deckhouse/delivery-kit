package build

import (
	"fmt"
	"path"
	"strings"

	imagePkg "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

// bootstrapImportOriginals reads off the recipe of the image which prepared sources the
// files it imports from a bootstrap source come from, as the verification reads them:
// per source image, the subtrees it declares and the path of the Packet each one stands
// at.
//
// A bootstrap image claims no composition of its own, so where a file sits in it says
// nothing about what it is. The recipe that imports the file is what states the prepared
// source behind it; that the source really serves those bytes at that path is settled
// against the pinned Packet itself.
//
// Only a source this very recipe imports as a bootstrap image can be mapped: a mapping
// for anything else would describe an import that does not happen.
func (phase *BuildPhase) bootstrapImportOriginals(img *imagePkg.Image, imports []scopedImportImage) (map[string][]nativegate.ImportOriginal, error) {
	if img.StapelImageConfig == nil || img.StapelImageConfig.ImageBaseConfig().ImageSpec == nil {
		return nil, nil
	}
	raw, present := img.StapelImageConfig.ImageBaseConfig().ImageSpec.Labels[sbomBuildContextLabel]
	if !present {
		return nil, nil
	}
	declaration, err := parseSBOMBuildContextDeclaration([]byte(raw))
	if err != nil {
		return nil, err
	}
	if len(declaration.BootstrapOriginals) == 0 {
		return nil, nil
	}

	bootstrap := make(map[string]bool, len(imports))
	for _, imported := range imports {
		if imported.bootstrap {
			bootstrap[imported.imageName] = true
		}
	}

	originals := make(map[string][]nativegate.ImportOriginal)
	for _, mapping := range declaration.BootstrapOriginals {
		if !bootstrap[mapping.SourceImage] {
			return nil, fmt.Errorf("image declares the originals of %q, which it does not import from as a bootstrap image", mapping.SourceImage)
		}
		originals[mapping.SourceImage] = append(originals[mapping.SourceImage], nativegate.ImportOriginal{
			Root:           mapping.Root,
			PackageName:    mapping.PackageName,
			PackageVersion: mapping.PackageVersion,
			OriginalPath:   mapping.OriginalPath,
		})
	}

	return originals, nil
}

// sbomBootstrapOriginalsChecksum states the declared mappings in the identity of the
// verification, so that a build which maps other bytes to other prepared sources is not
// answered by a document written for the mapping it replaced.
func sbomBootstrapOriginalsChecksum(originals []nativegate.ImportOriginal) []string {
	parts := make([]string, 0, len(originals)*4)
	for _, mapping := range originals {
		parts = append(parts, mapping.Root, mapping.OriginalPath, mapping.PackageName, mapping.PackageVersion)
	}

	return parts
}

// cleanRelativeOriginalPath answers whether a declared path names a place inside a
// Packet: the root of it, or something below the root.
func cleanRelativeOriginalPath(name string) bool {
	if name == "." {
		return true
	}

	return name != "" && !path.IsAbs(name) && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../")
}
