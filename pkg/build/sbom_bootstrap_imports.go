package build

import (
	"context"
	"fmt"
	"path"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/name"

	imagePkg "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	osPm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
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

// bootstrapImportPackages resolves, for every bootstrap source this image maps files of,
// the prepared sources that image's own recipe declares. Only a source something is
// mapped to is resolved: an unmapped import asks nothing of the registry.
func (phase *BuildPhase) bootstrapImportPackages(ctx context.Context, img *imagePkg.Image, imports []scopedImportImage, originals map[string][]nativegate.ImportOriginal) (map[string][]sources.Source, error) {
	if len(originals) == 0 {
		return nil, nil
	}
	packages := make(map[string][]sources.Source)
	for _, imported := range imports {
		if !imported.bootstrap || len(originals[imported.imageName]) == 0 {
			continue
		}
		if _, resolved := packages[imported.imageName]; resolved {
			continue
		}
		declared, err := phase.bootstrapSourcePackages(ctx, phase.Conveyor.GetImage(img.TargetPlatform, imported.imageName))
		if err != nil {
			return nil, err
		}
		packages[imported.imageName] = declared
	}

	return packages, nil
}

// bootstrapSourcePackages resolves the prepared sources the bootstrap image's own recipe
// declares its stages compile. A toolchain that builds itself opens no package receipt of
// its own - the compiler it ships was made from a source its recipe named, not installed
// by pm - so without this a mapping could name nothing but what pm happened to install
// there.
//
// Nothing of the declaration is taken on its word: the prepared source is the image the
// bootstrap recipe explicitly imports under that handle, pinned to the digest this build
// resolved, and the identity is read off that image's own pkg.* result labels and checked
// against what the declaration says it is - the same resolution a producer context does.
func (phase *BuildPhase) bootstrapSourcePackages(ctx context.Context, source *imagePkg.Image) ([]sources.Source, error) {
	if source == nil || source.StapelImageConfig == nil || source.StapelImageConfig.ImageBaseConfig().ImageSpec == nil {
		return nil, nil
	}
	raw, present := source.StapelImageConfig.ImageBaseConfig().ImageSpec.Labels[sbomBuildContextLabel]
	if !present {
		return nil, nil
	}
	declaration, err := parseSBOMBuildContextDeclaration([]byte(raw))
	if err != nil {
		return nil, err
	}

	var packages []sources.Source
	for _, stageName := range sbomBuildContextStageNames {
		declared, present := declaration.Stages[stageName]
		if !present {
			continue
		}
		for _, declaredPackage := range declared.Packages {
			candidate, err := phase.bootstrapSourcePackage(ctx, source, stageName, declaredPackage)
			if err != nil {
				return nil, err
			}
			packages = append(packages, candidate)
		}
	}

	return packages, nil
}

func (phase *BuildPhase) bootstrapSourcePackage(ctx context.Context, source *imagePkg.Image, stageName stage.StageName, declared sbomBuildContextPackage) (sources.Source, error) {
	imports, err := phase.producerSourceImports(ctx, source, stageName, declared.SourceImage)
	if err != nil {
		return sources.Source{}, fmt.Errorf("bootstrap image %q: %w", source.Name, err)
	}
	ref, err := name.NewDigest(imports[0].Reference, name.StrictValidation)
	if err != nil {
		return sources.Source{}, fmt.Errorf("no-data: producer source %s is not pinned: %w", declared.SourceImage, err)
	}
	config, err := nativegate.ReadPinnedOriginalConfig(ctx, imports[0].Reference, declared.SourcePlatform)
	if err != nil {
		return sources.Source{}, err
	}
	packet, err := osPm.PacketJSONFromImageLabels(ctx, config.Config.Labels, ref.DigestStr())
	if err != nil {
		return sources.Source{}, fmt.Errorf("producer source %s: %w", declared.SourceImage, err)
	}
	if err := checkProducerPacket(packet, declared); err != nil {
		return sources.Source{}, err
	}

	return sources.Source{Registry: ref.Context().Name(), Platform: declared.SourcePlatform, Packet: packet}, nil
}

// sbomBootstrapPackagesChecksum states the prepared sources a mapping may name in the
// identity of the verification: a bootstrap image whose recipe compiles another source
// is not answered by the document written while it compiled the one before.
func sbomBootstrapPackagesChecksum(packages []sources.Source) []string {
	parts := make([]string, 0, len(packages)*3)
	for _, candidate := range packages {
		parts = append(parts, candidate.Registry, candidate.Platform, string(candidate.Packet))
	}

	return parts
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
