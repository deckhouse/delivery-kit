package build

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/attestation"
	buildimage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/werf"
)

const (
	nativeContextMount    = "/.werf/sbom-build-context"
	nativeInstrumentation = "native-sbom-increment-1"
)

func nativeBootstrap(name string) bool {
	return name != "" && slices.Contains(strings.Split(os.Getenv("WERF_SBOM_BOOTSTRAP_IMAGES"), ","), name)
}

func validateNativeBootstrap(img *buildimage.Image) error {
	if nativeBootstrap(img.GetName()) {
		if img.IsFinal {
			return fmt.Errorf("bootstrap image %s cannot be final", img.GetName())
		}
		return nil
	}
	if nativeBootstrap(img.GetBaseImageName()) {
		return fmt.Errorf("bootstrap image %s cannot be used as from for strict image %s", img.GetBaseImageName(), img.GetName())
	}
	return nil
}

func nativeSBOMSettings() string {
	return util.Sha256Hash(nativeInstrumentation, os.Getenv("WERF_SBOM_PM_SHA256"), os.Getenv("WERF_SBOM_TRUSTED_INDEXES"), os.Getenv("WERF_SBOM_BOOTSTRAP_IMAGES"))
}

func nativeSBOMRepo(conveyor *Conveyor) string {
	if conveyor == nil || !conveyor.EnableSbom() {
		return ""
	}
	return conveyor.StorageManager.GetStagesStorage().Address()
}

func nativeArtifactChecksum(imageDigest, signerIdentity string, gostConfig gost.Config) string {
	return util.Sha256Hash(nativeSBOMSettings(), werf.Version, imageDigest, signerIdentity, gostConfig.AttackSurface.String(), gostConfig.SecurityFunction.String())
}

func nativeImportBackend(conveyor *Conveyor) string {
	if conveyor.UseLegacyStapelBuilder(conveyor.ContainerBackend) {
		return "rsync"
	}
	return "copy-recurse"
}

func nativePMOptions() nativegate.ReadPackageSourcesOptions {
	return nativegate.ReadPackageSourcesOptions{Binary: os.Getenv("WERF_SBOM_PM_BINARY"), SHA256: os.Getenv("WERF_SBOM_PM_SHA256")}
}

func nativeTrustedPackages(ctx context.Context, platform string) (nativegate.TrustedPackages, error) {
	var references []string
	if value := os.Getenv("WERF_SBOM_TRUSTED_INDEXES"); value != "" {
		references = strings.Split(value, ",")
	}
	return nativegate.LoadTrustedIndexes(ctx, references, platform)
}

func (phase *BuildPhase) nativeBaseLinks(ctx context.Context, img *buildimage.Image) (map[string]string, error) {
	if sbomImage.IsScratchRef(img.GetBaseImageReference()) || img.GetBaseImageReference() == "" {
		return map[string]string{}, nil
	}
	var info *image.Info
	if base := img.GetBaseStageImage(); base != nil && base.Image.GetStageDesc() != nil {
		info = base.Image.GetStageDesc().Info
	}
	if info == nil {
		var err error
		info, err = phase.Conveyor.ContainerBackend.GetImageInfo(ctx, img.GetBaseImageReference(), container_backend.GetImageInfoOpts{TargetPlatform: img.TargetPlatform})
		if err != nil {
			return nil, err
		}
	}
	if info == nil || info.Repository == "" || info.GetDigest() == "" {
		return nil, fmt.Errorf("base %s: no-data: missing pinned identity", img.GetBaseImageReference())
	}
	source, err := nativegate.ReadPinnedImage(ctx, info.Repository+"@"+info.GetDigest(), img.TargetPlatform)
	if err != nil {
		return nil, err
	}
	index, err := shippedscope.IndexImageFiles(ctx, source)
	if err != nil {
		return nil, err
	}
	if index.Incomplete {
		return nil, fmt.Errorf("base %s: incomplete filesystem", img.GetBaseImageReference())
	}
	return index.Symlinks, nil
}

func nativeUserRoots(ctx context.Context, img *buildimage.Image, cfg *v1.ConfigFile) ([]string, error) {
	var mappings []string
	for _, stg := range img.GetStages() {
		for _, mapping := range stg.GetGitMappings() {
			mappings = append(mappings, mapping.To)
		}
	}
	tmpdir := "/tmp"
	for _, env := range cfg.Config.Env {
		if value, ok := strings.CutPrefix(env, "TMPDIR="); ok && value != "" {
			tmpdir = value
		}
	}
	return nativegate.UserSourceRoots(ctx, mappings, cfg.Config.WorkingDir, tmpdir)
}

func (phase *BuildPhase) nativePackages(ctx context.Context, img *buildimage.Image, saved v1.Image, desc *image.StageDesc) (*nativegate.PackageSet, error) {
	directory, err := os.MkdirTemp(phase.Conveyor.tmpDir, "sbom-pm-state-")
	if err != nil {
		return nil, fmt.Errorf("create package state directory: %w", err)
	}
	defer os.RemoveAll(directory)
	provenance, err := resolveSBOMStageProvenance(ctx, desc, docker_registry.API().GetRepoImageConfigFile)
	if err != nil {
		return nil, err
	}
	var boundaries []int
	for _, snapshot := range provenance.Snapshots {
		boundaries = append(boundaries, snapshot.LayerCount)
	}
	views, err := shippedscope.CollectImageSnapshots(ctx, saved, provenance.DiffIDs, boundaries, shippedscope.CollectImageSnapshotsOptions{CaptureMatch: func(name string) bool { return name == "/var/lib/pm" || strings.HasPrefix(name, "/var/lib/pm/") }})
	if err != nil {
		return nil, err
	}
	var snapshots []nativegate.PackageSnapshot
	for _, snapshot := range provenance.Snapshots {
		required := snapshot.Stage == stage.Packages && img.StapelImageConfig != nil && len(img.StapelImageConfig.ImageBaseConfig().OSPMPackages()) > 0
		snapshots = append(snapshots, nativegate.PackageSnapshot{Stage: string(snapshot.Stage), View: views[snapshot.LayerCount], RequiresSources: required})
	}
	receipt, err := nativegate.CollectPackageSources(ctx, snapshots, directory, nativePMOptions())
	if err != nil {
		return nil, err
	}
	trusted, err := nativeTrustedPackages(ctx, img.TargetPlatform)
	if err != nil {
		return nil, err
	}
	set, err := nativegate.OpenPackageSet(ctx, receipt, img.TargetPlatform, trusted)
	if err != nil {
		return nil, fmt.Errorf("/var/lib/pm/sbom-sources.json: %w", err)
	}
	return set, nil
}

func (phase *BuildPhase) prepareNativeContext(ctx context.Context, img *buildimage.Image, stg stage.Interface) error {
	if !phase.Conveyor.EnableSbom() || img.StapelImageConfig == nil || !slices.Contains(jsObserverStageNames, stg.Name()) || nativeBootstrap(img.GetName()) {
		return nil
	}
	previous := phase.StagesIterator.GetPrevBuiltImage(img, stg)
	if previous == nil || previous.Image.GetStageDesc() == nil {
		return fmt.Errorf("%s: no-data: build context has no preceding stage", stg.Name())
	}
	desc := previous.Image.GetStageDesc()
	if err := phase.Conveyor.ContainerBackend.Pull(ctx, desc.Info.Name, container_backend.PullOpts{TargetPlatform: img.TargetPlatform}); err != nil {
		return err
	}
	saved, cleanup, err := savedImage(ctx, phase.Conveyor.ContainerBackend, desc.Info.Name)
	if err != nil {
		return err
	}
	defer cleanup()
	packages, err := phase.nativePackages(ctx, img, saved, desc)
	if err != nil {
		return err
	}
	trusted, err := nativeTrustedPackages(ctx, img.TargetPlatform)
	if err != nil {
		return err
	}
	if !sbomImage.IsScratchRef(img.GetBaseImageReference()) && img.GetBaseImageReference() != "" {
		base, err := phase.collectBaseImageSbom(ctx, img)
		if err != nil {
			return err
		}
		originals, err := nativegate.ImageOriginals(ctx, base, img.TargetPlatform)
		if err != nil {
			return err
		}
		if err := packages.IncludeImage(ctx, base, originals, img.TargetPlatform, trusted); err != nil {
			return err
		}
	}
	imports, err := phase.nativeImportOriginals(ctx, img, saved, desc)
	if err != nil {
		return err
	}
	for _, bom := range imports.BOMs {
		if err := packages.IncludeImage(ctx, bom, []nativegate.Original{}, img.TargetPlatform, trusted); err != nil {
			return err
		}
	}
	packages.Originals = append(packages.Originals, imports.Originals...)
	maps.Copy(packages.Symlinks, imports.Symlinks)
	if stg.Name() != stage.BeforeInstall {
		gitOriginals, gitLinks, err := nativeGitOriginals(ctx, img)
		if err != nil {
			return err
		}
		packages.Originals = append(packages.Originals, gitOriginals...)
		maps.Copy(packages.Symlinks, gitLinks)
	}
	baseLinks, err := phase.nativeBaseLinks(ctx, img)
	if err != nil {
		return err
	}
	maps.Copy(packages.Symlinks, baseLinks)
	cfg, err := saved.ConfigFile()
	if err != nil {
		return err
	}
	roots, err := nativeUserRoots(ctx, img, cfg)
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp(phase.Conveyor.tmpDir, "sbom-build-context-")
	if err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		return err
	}
	filename, err := nativegate.MaterializeBuildContext(ctx, saved, packages, directory, nativegate.ContextOptions{Subject: img.GetName(), Platform: img.TargetPlatform, UserRoots: roots, ContainerRoot: nativeContextMount})
	if err != nil {
		return err
	}
	volumes := []string{directory + ":" + nativeContextMount + ":ro"}
	env := map[string]string{"SBOM_BUILD_CONTEXT": filename}
	builder := stg.GetStageImage().Builder
	if phase.Conveyor.UseLegacyStapelBuilder(phase.Conveyor.ContainerBackend) {
		builder.LegacyStapelStageBuilder().Container().RunOptions().AddVolume(volumes...)
		builder.LegacyStapelStageBuilder().Container().AddBuildTimeEnv(env)
	} else {
		builder.StapelStageBuilder().AddBuildVolumes(volumes...)
		builder.StapelStageBuilder().AddBuildTimeEnvs(env)
	}
	return nil
}

func nativeGitOriginals(ctx context.Context, img *buildimage.Image) ([]nativegate.Original, map[string]string, error) {
	var result []nativegate.Original
	symlinks := map[string]string{}
	seen := map[*stage.GitMapping]bool{}
	for _, stg := range img.GetStages() {
		for _, mapping := range stg.GetGitMappings() {
			if seen[mapping] {
				continue
			}
			seen[mapping] = true
			source, err := mapping.SBOMSource(ctx)
			if err != nil {
				return nil, nil, err
			}
			maps.Copy(symlinks, source.Symlinks)
			locator := source.Repository
			identity := locator + "@" + source.Commit
			component := cdx.Component{Type: cdx.ComponentTypeApplication, BOMRef: "urn:dk:git:" + util.Sha256Hash(identity), Name: img.GetName(), Version: source.Commit, PackageURL: packageurl.NewPackageURL(packageurl.TypeGeneric, "", img.GetName(), source.Commit, packageurl.Qualifiers{{Key: "source_kind", Value: "git"}, {Key: "source_locator", Value: locator}}, "").ToString(), ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeVCS, URL: locator}}, Properties: &[]cdx.Property{{Name: "dk:git-commit", Value: source.Commit}}}
			if locator == "." {
				component.ExternalReferences = nil
			}
			for _, name := range slices.Sorted(maps.Keys(source.Files)) {
				result = append(result, nativegate.Original{Path: name, SHA256: source.Files[name], Component: component, Kind: "git"})
			}
		}
	}
	return result, symlinks, nil
}

type nativeImportedSources struct {
	Originals  []nativegate.Original
	Components []cdx.Component
	BOMs       []*cdx.BOM
	Symlinks   map[string]string
}

func (phase *BuildPhase) nativeImportOriginals(ctx context.Context, img *buildimage.Image, saved v1.Image, desc *image.StageDesc) (nativeImportedSources, error) {
	if err := ctx.Err(); err != nil {
		return nativeImportedSources{}, err
	}
	if len(img.GetImportImagesInfo()) == 0 {
		return nativeImportedSources{}, nil
	}
	provenance, err := resolveSBOMStageProvenance(ctx, desc, docker_registry.API().GetRepoImageConfigFile)
	if err != nil {
		return nativeImportedSources{}, err
	}
	boundaries := make([]int, 0, len(provenance.Snapshots))
	for _, snapshot := range provenance.Snapshots {
		boundaries = append(boundaries, snapshot.LayerCount)
	}
	views, err := shippedscope.CollectImageSnapshots(ctx, saved, provenance.DiffIDs, boundaries, shippedscope.CollectImageSnapshotsOptions{})
	if err != nil {
		return nativeImportedSources{}, err
	}
	var result []nativegate.Original
	var components []cdx.Component
	var boms []*cdx.BOM
	symlinks := map[string]string{}
	for position, snapshot := range provenance.Snapshots {
		stg := img.GetStage(snapshot.Stage)
		if stg == nil {
			continue
		}
		dependency, ok := stg.(interface{ GetImports() []*config.Import })
		if !ok || len(dependency.GetImports()) == 0 {
			continue
		}
		if position == 0 {
			return nativeImportedSources{}, fmt.Errorf("%s: no-data: import has no previous snapshot", snapshot.Stage)
		}
		backend := nativegate.ImportBackendCopyRecurse
		if snapshot.ImportBackend == "rsync" {
			backend = nativegate.ImportBackendRsync
		} else if snapshot.ImportBackend != "copy-recurse" {
			return nativeImportedSources{}, fmt.Errorf("%s: no-data: missing import backend", snapshot.Stage)
		}
		for _, directive := range dependency.GetImports() {
			var info *image.Info
			lookup := ""
			if directive.ExternalImage {
				info, err = phase.Conveyor.ContainerBackend.GetImageInfo(ctx, directive.From, container_backend.GetImageInfoOpts{TargetPlatform: img.TargetPlatform})
			} else {
				source := phase.Conveyor.GetImage(img.TargetPlatform, directive.From)
				if source != nil {
					info = source.GetLastNonEmptyStageImageInfo()
				}
				lookup = directive.From
			}
			if err != nil {
				return nativeImportedSources{}, err
			}
			if info == nil {
				return nativeImportedSources{}, fmt.Errorf("%s: no-data: import image %s missing", directive.Add, directive.From)
			}
			bootstrap := !directive.ExternalImage && nativeBootstrap(directive.From)
			var bom *cdx.BOM
			var originals []nativegate.Original
			if !bootstrap {
				bom, err = phase.sbomStep.pullImageSbom(ctx, lookup, info)
				if err != nil {
					return nativeImportedSources{}, fmt.Errorf("%s: import %s has no SBOM: %w", directive.Add, directive.From, err)
				}
				originals, err = nativegate.ImageOriginals(ctx, bom, img.TargetPlatform)
				if err != nil {
					return nativeImportedSources{}, err
				}
			}

			if err := phase.Conveyor.ContainerBackend.Pull(ctx, info.Name, container_backend.PullOpts{TargetPlatform: img.TargetPlatform}); err != nil {
				return nativeImportedSources{}, err
			}
			sourceImage, cleanup, err := savedImage(ctx, phase.Conveyor.ContainerBackend, info.Name)
			if err != nil {
				return nativeImportedSources{}, err
			}
			sourceIndex, indexErr := shippedscope.IndexImageFiles(ctx, sourceImage)
			cleanup()
			if indexErr != nil {
				return nativeImportedSources{}, indexErr
			}
			if bootstrap {
				component := cdx.Component{Type: cdx.ComponentTypeData, BOMRef: "urn:dk:bootstrap:" + info.GetDigest(), Name: directive.From, Version: info.GetDigest(), ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: "oci://" + info.Repository + "@" + info.GetDigest()}}}
				for name, file := range sourceIndex.Files {
					originals = append(originals, nativegate.Original{Path: name, SHA256: file.Digest, Component: component, Kind: "bootstrap"})
				}
			}

			projected, err := nativegate.ProjectImageOriginals(ctx, originals, sourceIndex, views[provenance.Snapshots[position-1].LayerCount].Index, views[snapshot.LayerCount].Index, nativegate.ImportScope{Backend: backend, FromPath: directive.Add, ToPath: directive.To, IncludePaths: directive.IncludePaths, ExcludePaths: directive.ExcludePaths})
			if err != nil {
				return nativeImportedSources{}, err
			}
			result = append(result, projected...)
			links, err := nativegate.ProjectImageSymlinks(ctx, sourceIndex, views[provenance.Snapshots[position-1].LayerCount].Index, views[snapshot.LayerCount].Index, nativegate.ImportScope{Backend: backend, FromPath: directive.Add, ToPath: directive.To, IncludePaths: directive.IncludePaths, ExcludePaths: directive.ExcludePaths})
			if err != nil {
				return nativeImportedSources{}, err
			}
			maps.Copy(symlinks, links)
			if bom != nil {
				components = append(components, (*bom.Components)...)
				boms = append(boms, bom)
			}
		}
	}
	return nativeImportedSources{Originals: result, Components: components, BOMs: boms, Symlinks: symlinks}, nil
}

func (phase *BuildPhase) convergeNativeSBOM(ctx context.Context, img *buildimage.Image, base *cdx.BOM, external BOMPatcherInterface, gostConfig gost.Config, signer signature.Signer, signerIdentity string) error {
	desc := img.GetLastNonEmptyStageDesc()
	checksum := nativeArtifactChecksum(desc.Info.GetDigest(), signerIdentity, gostConfig)
	store := artifact.NewOCIStore(desc.Info.Repository, img.GetName())
	cached, found, err := attestation.FindAttachedArtifact(ctx, store, desc.Info.GetDigest(), attestation.PredicateKindCycloneDX)
	if err != nil {
		return err
	}
	if found && cached.Annotations[image.WerfChecksumAnnotation] == checksum {
		logboek.Context(ctx).Default().LogF("image %s: Use previously generated SBOM from registry\n", img.GetName())
		return nil
	}
	if err := phase.Conveyor.ContainerBackend.Pull(ctx, desc.Info.Name, container_backend.PullOpts{TargetPlatform: img.TargetPlatform}); err != nil {
		return err
	}
	saved, cleanup, err := savedImage(ctx, phase.Conveyor.ContainerBackend, desc.Info.Name)
	if err != nil {
		return err
	}
	defer cleanup()
	packages, err := phase.nativePackages(ctx, img, saved, desc)
	if err != nil {
		return err
	}
	cfg, err := saved.ConfigFile()
	if err != nil {
		return err
	}
	roots, err := nativeUserRoots(ctx, img, cfg)
	if err != nil {
		return err
	}
	opts := nativegate.VerifyOptions{Platform: img.TargetPlatform, Subject: img.GetName(), UserRoots: roots, Originals: packages.Originals, TrustedComponents: packages.Components}
	if !sbomImage.IsScratchRef(img.GetBaseImageReference()) && img.GetBaseImageReference() != "" {
		originals, err := nativegate.ImageOriginals(ctx, base, img.TargetPlatform)
		if err != nil {
			return fmt.Errorf("base %s: %w", img.GetBaseImageReference(), err)
		}
		opts.Originals = append(opts.Originals, originals...)
		opts.TrustedComponents = append(opts.TrustedComponents, (*base.Components)...)
	}
	gitOriginals, gitSymlinks, err := nativeGitOriginals(ctx, img)
	if err != nil {
		return err
	}
	opts.Originals = append(opts.Originals, gitOriginals...)
	opts.ExpectedSymlinks = maps.Clone(packages.Symlinks)
	if opts.ExpectedSymlinks == nil {
		opts.ExpectedSymlinks = map[string]string{}
	}
	maps.Copy(opts.ExpectedSymlinks, gitSymlinks)
	imports, err := phase.nativeImportOriginals(ctx, img, saved, desc)
	if err != nil {
		return err
	}
	opts.Originals = append(opts.Originals, imports.Originals...)
	maps.Copy(opts.ExpectedSymlinks, imports.Symlinks)
	baseLinks, err := phase.nativeBaseLinks(ctx, img)
	if err != nil {
		return err
	}
	maps.Copy(opts.ExpectedSymlinks, baseLinks)
	opts.TrustedComponents = append(opts.TrustedComponents, imports.Components...)
	bom := cyclonedxutil.NewBOM()
	restoreImageMetadata(bom, desc)
	cyclonedxutil.MarkWerfTool(bom, werf.Version)
	if err := nativegate.Verify(ctx, saved, bom, opts); err != nil {
		return fmt.Errorf("verify image %s: %w", img.GetName(), err)
	}
	bom, err = patchBOM(ctx, bom, nil, external, gostConfig)
	if err != nil {
		return err
	}
	data, err := cyclonedxutil.ToJSON(bom)
	if err != nil {
		return err
	}
	if err := cyclonedxutil.ValidateCycloneDX16Schema(data); err != nil {
		return err
	}
	return sbomImage.PushSBOM(ctx, data, desc.Info.Repository, desc.Info.GetDigest(), img.GetName(), checksum, img.TargetPlatform, signer)
}
