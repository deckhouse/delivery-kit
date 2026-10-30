package build

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v3/pkg/sbom/declared"
	"github.com/werf/werf/v3/pkg/sbom/externalref"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/managedinput"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/storage"
	"github.com/werf/werf/v3/pkg/tmp_manager"
	"github.com/werf/werf/v3/pkg/werf"
)

//go:generate mockgen -source sbom_step.go -package mock -destination ../../test/mock/bom_patcher.go -mock_names BOMPatcherInterface=MockBOMPatcher

type BOMPatcherInterface interface {
	Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error)
}

type sbomStep struct {
	containerBackend container_backend.ContainerBackend
	stagesStorage    storage.StagesStorage

	gostWarnOnce sync.Once
}

func newSbomStep(
	backend container_backend.ContainerBackend,
	stagesStorage storage.StagesStorage,
) *sbomStep {
	return &sbomStep{
		containerBackend: backend,
		stagesStorage:    stagesStorage,
	}
}

func syftScanRequired(isStapel bool, catalogers []scanner.Cataloger) bool {
	return !isStapel || len(catalogers) > 0
}

// ConvergeWithMergeOptions carries the inputs of one convergence that belong to the image
// being converged. They are passed per call rather than held by the step, which is shared
// between the images converged in parallel.
type ConvergeWithMergeOptions struct {
	// Sources are the import directives of the image, in build order, each pinned to the
	// source image the build copied from.
	Sources []sbomSourceImportInput
}

// ConvergeWithMerge produces, caches and pushes the SBOM of one built image. osPmPackages
// is the union of the os-pm directive specs of the image, the entries as written in
// werf.yaml; when non-empty, the pm index of the image is read and the declared packages
// recorded.
func (step *sbomStep) ConvergeWithMerge(ctx context.Context, werfImgName string, stageDesc *image.StageDesc, scanOpts scanner.ScanOptions, mergeOpts cyclonedxutil.MergeOpts, patchers []BOMPatcherInterface, osPmPackages []string, isStapel bool, targetPlatform string, signer signature.Signer, signerIdentity string, opts ...ConvergeWithMergeOptions) error {
	if len(opts) > 1 {
		return fmt.Errorf("image %s: more than one set of convergence options", werfImgName)
	}
	var options ConvergeWithMergeOptions
	if len(opts) == 1 {
		options = opts[0]
	}

	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	scanOpts.Commands[0].SourcePath = stageDesc.Info.Name
	catalogers := scanOpts.Commands[0].Catalogers

	if err := step.prepareGostComponents(ctx, &mergeOpts); err != nil {
		return err
	}

	if !isStapel {
		return fmt.Errorf("image %s: no-data: the composition of the image cannot be verified, only a Stapel image carries the stage provenance the verification reads", werfImgName)
	}
	provenance, err := resolveSBOMStageProvenance(ctx, stageDesc, docker_registry.API().GetRepoImageConfigFile)
	if err != nil {
		return fmt.Errorf("image %s: no-data: the stage provenance of the image is unknown: %w", werfImgName, err)
	}

	policy := nativegate.NewDefaultPolicy(ctx, werfImgName)
	policyChecksum, err := sbomPolicyChecksum(policy)
	if err != nil {
		return err
	}
	checksum := util.Sha256Hash(
		step.calculateStableChecksum(scanOpts, mergeOpts, signerIdentity, targetPlatform, provenance),
		"policy", policyChecksum,
		"sources", sbomSourceImportsChecksum(options.Sources),
	)

	store := artifact.NewOCIStore(repo, werfImgName)

	desc, found, err := attestation.FindAttachedArtifact(ctx, store, parentDigest, attestation.PredicateKindCycloneDX)
	if err != nil {
		return fmt.Errorf("check SBOM cache: %w", err)
	}
	// What is already published is reused as a publication only: every check below runs
	// first, and the checksum then decides whether the result has to be pushed again.
	var publishedChecksum string
	if found {
		publishedChecksum = desc.Annotations[image.WerfChecksumAnnotation]
	}

	if err := step.containerBackend.Pull(ctx, stageDesc.Info.Name, container_backend.PullOpts{TargetPlatform: targetPlatform}); err != nil {
		return fmt.Errorf("unable to pull %q: %w", stageDesc.Info.Name, err)
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: SBOM processing", werfImgName).DoError(func() error {
		var targetBOM *cdx.BOM

		img, cleanup, err := savedImage(ctx, step.containerBackend, stageDesc.Info.Name)
		if err != nil {
			return err
		}
		defer cleanup()

		verifiedBOM, err := step.verifyImageComposition(ctx, werfImgName, stageDesc, img, provenance, policy, mergeOpts.BaseBOM, options.Sources, targetPlatform)
		if err != nil {
			return err
		}

		switch {
		case !syftScanRequired(isStapel, catalogers):
			targetBOM = cyclonedxutil.NewBOM()
			restoreImageMetadata(targetBOM, stageDesc)
		case isStapel:
			var err error
			targetBOM, err = step.scanFileBasedPackages(ctx, stageDesc.Info, scanOpts, catalogers, targetPlatform)
			if err != nil {
				return err
			}
			restoreImageMetadata(targetBOM, stageDesc)
		default:
			bomJSON, err := step.containerBackend.GenerateSBOM(ctx, scanOpts)
			if err != nil {
				return fmt.Errorf("generate SBOM: %w", err)
			}

			targetBOM, err = cyclonedxutil.BuildCycloneDX16BOMFromJSON(bomJSON)
			if err != nil {
				return fmt.Errorf("parse scanned BOM: %w", err)
			}
			cyclonedxutil.MarkWerfTool(targetBOM, werf.Version)
		}

		var filesets *shippedscope.Filesets
		produced := &shippedscope.ProducedFiles{}
		inputs := append([]*cdx.BOM{targetBOM, mergeOpts.BaseBOM}, mergeOpts.ImportBOMs...)
		if isStapel || len(osPmPackages) > 0 || lo.SomeBy(inputs, func(bom *cdx.BOM) bool {
			return bom != nil && (shippedscope.HasFileBackedComponents(bom) || shippedscope.HasBinaryBackedComponents(ctx, bom))
		}) {
			filesets, produced = collectShippedScope(ctx, img, werfImgName, stageDesc.Info.Name, provenance)
		}
		if isStapel && filesets != nil {
			installedBOMs, err := step.scanInstalledPackages(ctx, stageDesc.Info, scanOpts, filesets.Index, targetPlatform)
			if err != nil {
				return err
			}
			mergeOpts.ImportBOMs = append(slices.Clone(mergeOpts.ImportBOMs), installedBOMs...)
		}
		mergeOpts, err = prepareBinaryMerge(ctx, targetBOM, mergeOpts, produced)
		if err != nil {
			return err
		}

		resultBOM := targetBOM
		if !mergeOpts.IsEmpty() {
			var err error
			resultBOM, err = cyclonedxutil.MergeBOMs(ctx, targetBOM, mergeOpts)
			if err != nil {
				return fmt.Errorf("merge BOMs: %w", err)
			}
		}

		cyclonedxutil.Canonicalize(ctx, resultBOM)

		// The file evidence of the scanned document is marked before the verified
		// composition is grafted on, so that what the image was proven to be made of is
		// never classified by the inventory the scan inherited.
		recordShippedScope(ctx, resultBOM, filesets, produced, werfImgName)

		if dropped := shippedscope.DropBinaryAttributionForVerifiedPaths(ctx, resultBOM, verifiedBinaryContents(verifiedBOM)); dropped > 0 {
			logboek.Context(ctx).Debug().LogF("image %s: %d guessed module components replaced by the composition of the binaries they were read from\n", werfImgName, dropped)
		}

		resultBOM, err = cyclonedxutil.MergeBOMs(ctx, resultBOM, cyclonedxutil.MergeOpts{ImportBOMs: []*cdx.BOM{verifiedBOM}})
		if err != nil {
			return fmt.Errorf("merge verified composition: %w", err)
		}

		if len(osPmPackages) > 0 {
			// Only a component bound to an original source is a package the image was proven
			// to be made of. A composition claim read out of a binary can carry the same name
			// and version without being one, so the directive is matched against a view of the
			// result holding the former alone — and the refs it returns are the result's own.
			declaredPkgs := declared.FromOSPMSpec(osPmPackages)
			originals := &cdx.BOM{
				Dependencies: resultBOM.Dependencies,
				Components: lo.ToPtr(lo.Filter(lo.FromPtr(resultBOM.Components), func(comp cdx.Component, _ int) bool {
					return comp.Type == cdx.ComponentTypeLibrary && lo.SomeBy(lo.FromPtr(comp.Properties), func(property cdx.Property) bool {
						return property.Name == cyclonedxutil.PropertyOriginalSource
					})
				})),
			}
			if resultBOM.Metadata != nil && resultBOM.Metadata.Component != nil {
				originals.Metadata = &cdx.Metadata{Component: &cdx.Component{BOMRef: resultBOM.Metadata.Component.BOMRef}}
			}
			refs, unmatched := declared.MatchComponents(ctx, originals, config.PackagesDirectiveTypeOSPM, declaredPkgs)
			if len(unmatched) > 0 {
				unmatchedNames := lo.SliceToMap(unmatched, func(pkg declared.Package) (string, struct{}) { return pkg.Name, struct{}{} })
				entries := lo.Filter(osPmPackages, func(entry string, _ int) bool {
					_, ok := unmatchedNames[declared.OSPMSpecName(entry)]
					return ok
				})
				return fmt.Errorf("record declared os-pm packages of image %q as its attack surface: %s left no verified file in the image, so nothing proves the image is made of them", werfImgName, strings.Join(entries, ", "))
			}
			declared.AddRootEdge(resultBOM, refs)
		}

		for _, patcher := range patchers {
			if patcher == nil {
				continue
			}
			if _, isExternalRef := patcher.(*externalref.ExternalRefPatcher); isExternalRef {
				if err := logboek.Context(ctx).Default().LogProcess("Resolve external references").DoError(func() error {
					patchedBOM, applyErr := patcher.Apply(ctx, resultBOM)
					if applyErr != nil {
						if errors.Is(applyErr, externalref.ErrExternalRefEnrich) {
							logboek.Context(ctx).Warn().LogF("WARNING: %s\n", applyErr)
						}
						return applyErr
					}
					resultBOM = patchedBOM
					return nil
				}); err != nil {
					return err
				}
				continue
			}
			resultBOM, err = patcher.Apply(ctx, resultBOM)
			if err != nil {
				return err
			}
		}

		if err := gost.Upsert(resultBOM, mergeOpts.Gost); err != nil {
			return fmt.Errorf("set GOST properties: %w", err)
		}

		cyclonedxutil.Canonicalize(ctx, resultBOM)

		graftVerifiedProperties(resultBOM, verifiedBOM)

		resultJSON, err := cyclonedxutil.ToJSON(resultBOM)
		if err != nil {
			return fmt.Errorf("serialize BOM: %w", err)
		}

		if err := cyclonedxutil.ValidateCycloneDX16Schema(resultJSON); err != nil {
			return fmt.Errorf("validate BOM: %w", err)
		}

		if publishedChecksum == checksum {
			logboek.Context(ctx).Default().LogF("image %s: composition verified; the SBOM already in the registry describes it\n", werfImgName)
			return nil
		}

		if err := logboek.Context(ctx).Default().LogProcess("Push SBOM artifact").DoError(func() error {
			return sbomImage.PushSBOM(ctx, resultJSON, repo, parentDigest, werfImgName, checksum, targetPlatform, signer)
		}); err != nil {
			return err
		}

		return nil
	})
}

// verifyImageComposition establishes what the image is made of from the stage boundaries
// it was built through and the original sources they carry, under the default policy. It
// is the authority on the packages of the image; the scan that runs beside it contributes
// the language ecosystems the composition says nothing about.
func (step *sbomStep) verifyImageComposition(ctx context.Context, werfImgName string, stageDesc *image.StageDesc, img v1.Image, provenance sbomStageProvenance, policy *nativegate.Policy, baseBOM *cdx.BOM, sources []sbomSourceImportInput, targetPlatform string) (*cdx.BOM, error) {
	snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
	if err != nil {
		return nil, fmt.Errorf("verify the composition of image %s: %w", werfImgName, err)
	}
	captured, err := captureSBOMSourceImages(ctx, step.containerBackend, sources, targetPlatform)
	if err != nil {
		return nil, fmt.Errorf("verify the composition of image %s: %w", werfImgName, err)
	}
	sourceSnapshots, err := sbomSourceGateSnapshots(snapshots, sources, captured)
	if err != nil {
		return nil, fmt.Errorf("verify the composition of image %s: %w", werfImgName, err)
	}

	verified := cyclonedxutil.NewBOM()
	restoreImageMetadata(verified, stageDesc)
	if err := nativegate.ApplySourceSnapshots(ctx, policy, werfImgName, img, sourceSnapshots, verified, nativegate.ApplySourceSnapshotsOptions{BaseBOM: baseBOM}); err != nil {
		return nil, fmt.Errorf("verify the composition of image %s: %w", werfImgName, err)
	}
	logboek.Context(ctx).Default().LogF("image %s: composition verified against its original sources\n", werfImgName)

	return verified, nil
}

// verifiedBinaryContents is what the verification established the image holds, by path:
// the file components of its document name the path and carry the content's digest.
func verifiedBinaryContents(verified *cdx.BOM) map[string]string {
	contents := make(map[string]string)
	for _, comp := range lo.FromPtr(verified.Components) {
		if comp.Type != cdx.ComponentTypeFile {
			continue
		}
		for _, hash := range lo.FromPtr(comp.Hashes) {
			if hash.Algorithm == cdx.HashAlgoSHA256 {
				contents[comp.Name] = "sha256:" + hash.Value
			}
		}
	}

	return contents
}

func sbomPolicyChecksum(policy *nativegate.Policy) (string, error) {
	data, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("read the composition policy: %w", err)
	}

	return util.Sha256Hash(string(data)), nil
}

// graftVerifiedProperties puts the catalog of the verified composition onto the result. A
// merge keeps the metadata of its target, so the properties the verification wrote travel
// separately; they are copied last, over any same-named property, and no other property
// of the document is touched.
func graftVerifiedProperties(target, verified *cdx.BOM) {
	if target == nil || verified == nil || verified.Metadata == nil {
		return
	}
	var grafted []cdx.Property
	replaced := make(map[string]bool)
	for _, property := range lo.FromPtr(verified.Metadata.Properties) {
		if !strings.HasPrefix(property.Name, verifiedPropertyPrefix) {
			continue
		}
		replaced[property.Name] = true
		grafted = append(grafted, property)
	}
	if len(grafted) == 0 {
		return
	}
	if target.Metadata == nil {
		target.Metadata = &cdx.Metadata{}
	}
	kept := lo.Filter(lo.FromPtr(target.Metadata.Properties), func(property cdx.Property, _ int) bool {
		return !replaced[property.Name]
	})
	target.Metadata.Properties = lo.ToPtr(append(kept, grafted...))
}

const verifiedPropertyPrefix = "dk:"

// dropSupersededPackageAttribution removes from an inherited document the package
// attribution the verified composition of this image establishes anew: the pm packages an
// image recorded from its pm index, the ones it recorded from original sources, and the
// composition claims it read out of the binaries it carried. The verification rebuilds all
// three for the binaries this image actually holds, so what a donor claimed about a binary
// an import left behind would otherwise survive as a package of this image. The purl-less
// file components of a directory scan go with them. Language package evidence — Go,
// Python, Node — is not attribution of this kind and stays.
func dropSupersededPackageAttribution(bom *cdx.BOM) {
	cyclonedxutil.DropSyftSourceFileComponents(bom)
	if bom == nil || bom.Components == nil {
		return
	}
	kept := lo.Filter(*bom.Components, func(comp cdx.Component, _ int) bool {
		return !supersededPackageAttribution(comp)
	})
	if len(kept) == 0 {
		bom.Components = nil

		return
	}
	*bom.Components = kept
}

func supersededPackageAttribution(comp cdx.Component) bool {
	if comp.Type != cdx.ComponentTypeLibrary {
		return false
	}
	for _, property := range lo.FromPtr(comp.Properties) {
		if property.Name == cyclonedxutil.PropertyOriginalSource || property.Name == nativeCompositionProperty {
			return true
		}
	}
	purl, err := packageurl.FromString(comp.PackageURL)
	if err != nil || purl.Type != packageurl.TypeGeneric {
		return false
	}
	qualifiers := purl.Qualifiers.Map()
	if _, pmAttributed := qualifiers["containerfactoryversion"]; pmAttributed {
		return true
	}
	_, kind := qualifiers["source_kind"]
	_, locator := qualifiers["source_locator"]

	return kind && locator
}

// nativeCompositionProperty is what a component read out of a binary's embedded
// composition carries. The verification writes it; an inherited one is a donor's claim.
const nativeCompositionProperty = "dk:source"

// collectShippedScope reads the built image the caller already holds: one convergence
// reads it once, for the verification and for the file evidence both.
func collectShippedScope(ctx context.Context, img v1.Image, werfImgName, imageName string, provenance sbomStageProvenance) (*shippedscope.Filesets, *shippedscope.ProducedFiles) {
	unknown := &shippedscope.ProducedFiles{}

	filesets, err := shippedscope.CollectFilesets(ctx, img)
	if err != nil {
		logboek.Context(ctx).Warn().LogF("WARNING: image %s: unable to read which files the components of the built image %s consist of; installed package inventory and file evidence are incomplete: %s\n", werfImgName, imageName, err)

		return nil, unknown
	}

	if !provenance.Layers.Known {
		return filesets, unknown
	}
	cfg, err := img.ConfigFile()
	if err != nil || cfg == nil || !slices.Equal(cfg.RootFS.DiffIDs, provenance.DiffIDs) {
		logboek.Context(ctx).Warn().LogF("WARNING: image %s: saved image does not match the stage provenance; produced binaries are unknown\n", werfImgName)

		return filesets, unknown
	}
	produced, err := shippedscope.CollectProducedFiles(ctx, img, filesets.Index, provenance.Layers)
	if err != nil {
		logboek.Context(ctx).Warn().LogF("WARNING: image %s: unable to collect produced binaries: %s\n", werfImgName, err)

		return filesets, unknown
	}

	return filesets, produced
}

func prepareBinaryMerge(ctx context.Context, target *cdx.BOM, opts cyclonedxutil.MergeOpts, produced *shippedscope.ProducedFiles) (cyclonedxutil.MergeOpts, error) {
	shippedscope.PrepareBinaryOccurrences(ctx, target, produced)
	inputs := append([]*cdx.BOM{opts.BaseBOM}, opts.ImportBOMs...)
	for i, input := range inputs {
		if input == nil {
			continue
		}
		clone, err := cyclonedxutil.CloneBOM(input)
		if err != nil {
			return opts, fmt.Errorf("clone binary evidence source: %w", err)
		}
		shippedscope.NormalizeInheritedBinaryOccurrences(ctx, clone)
		dropSupersededPackageAttribution(clone)
		inputs[i] = clone
	}
	opts.BaseBOM = inputs[0]
	opts.ImportBOMs = inputs[1:]

	return opts, nil
}

func recordShippedScope(ctx context.Context, bom *cdx.BOM, filesets *shippedscope.Filesets, produced *shippedscope.ProducedFiles, werfImgName string) {
	shippedscope.RecordProducedBinaryOccurrences(ctx, bom, produced)
	if filesets == nil {
		return
	}
	recorded := shippedscope.RecordOccurrences(bom, filesets.Filesets)
	logboek.Context(ctx).Debug().LogF("Collected %d component filesets of the image, recorded onto %d components\n", len(filesets.Filesets), recorded)

	if marked := shippedscope.MarkNotShipped(ctx, bom, filesets); marked > 0 {
		logboek.Context(ctx).Default().LogF("image %s: %d components of the SBOM are not shipped by the image\n", werfImgName, marked)
	}
}

// savedImage reads the image out of the backend as a docker-save tarball. The tarball is
// read more than once, once for its manifest and once per layer, which a stream cannot
// give, so it goes to a file first, the same way MutateAndPushImage does. The returned
// cleanup removes that file.
func savedImage(ctx context.Context, backend imageSaver, imageName string) (v1.Image, func(), error) {
	stream, err := backend.SaveImageToStream(ctx, imageName)
	if err != nil {
		return nil, nil, fmt.Errorf("save image: %w", err)
	}
	defer stream.Close()

	file, err := tmp_manager.TempFile("werf-sbom-shipped-files-*.tar")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp file: %w", err)
	}
	cleanup := func() { _ = os.Remove(file.Name()) }

	if _, err := io.Copy(file, stream); err != nil {
		_ = file.Close()
		cleanup()

		return nil, nil, fmt.Errorf("write saved image to %s: %w", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		cleanup()

		return nil, nil, fmt.Errorf("close %s: %w", file.Name(), err)
	}

	img, err := tarball.ImageFromPath(file.Name(), nil)
	if err != nil {
		cleanup()

		return nil, nil, fmt.Errorf("read saved image %s: %w", file.Name(), err)
	}

	return img, cleanup, nil
}

// restoreImageMetadata sets the BOM's top-level component to the scanned image while
// keeping any syft-provided metadata (tools, timestamp). A directory source reports the
// temporary scan directory as its component, so it must be replaced; the dependency edges
// sourced at it — the packages the image declares — are moved onto the image. When no
// timestamp is present — the skip-scan path builds a fresh BOM — one is stamped, since a
// per-image SBOM without a timestamp is rejected by downstream validators.
func restoreImageMetadata(bom *cdx.BOM, stageDesc *image.StageDesc) {
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	container := containerComponent(stageDesc)
	if previous := bom.Metadata.Component; previous != nil && previous.BOMRef != "" && container.BOMRef != "" && previous.BOMRef != container.BOMRef {
		cyclonedxutil.RewriteRefs(bom, map[string]string{previous.BOMRef: container.BOMRef})
	}
	bom.Metadata.Component = container
	if bom.Metadata.Timestamp == "" {
		bom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	cyclonedxutil.MarkWerfTool(bom, werf.Version)
}

// containerComponent builds the top-level container component of an image BOM. Its
// bom-ref is the OCI purl of the image, so that the edges sourced at it survive a merge
// into another image's BOM under a ref that still names this image.
func containerComponent(stageDesc *image.StageDesc) *cdx.Component {
	comp := &cdx.Component{
		Type:    cdx.ComponentTypeContainer,
		Name:    stageDesc.Info.Repository,
		Version: stageDesc.Info.Tag,
	}
	if digest := stageDesc.Info.GetDigest(); digest != "" {
		comp.PackageURL = imagePURL(stageDesc.Info, digest)
		comp.BOMRef = comp.PackageURL
	}
	return comp
}

// imagePURL builds the pkg:oci purl of an image: the last path segment of the repository
// is the name and the manifest digest the version, as the purl spec prescribes for OCI
// images; the repository and tag go into qualifiers.
func imagePURL(info *image.Info, digest string) string {
	name := info.Repository
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	qualifiers := packageurl.Qualifiers{{Key: "repository_url", Value: info.Repository}}
	if info.Tag != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "tag", Value: info.Tag})
	}
	return packageurl.NewPackageURL(packageurl.TypeOCI, "", strings.ToLower(name), digest, qualifiers, "").ToString()
}

// scanFileBasedPackages catalogs the file-based packages of a stapel image by scanning,
// per directive, only the spec/lock files extracted from the built image (a directory
// source), then unions the per-directive BOMs. This avoids walking the whole image
// filesystem and needs no docker.sock in the scanner container.
func (step *sbomStep) scanFileBasedPackages(ctx context.Context, imageInfo *image.Info, scanOpts scanner.ScanOptions, catalogers []scanner.Cataloger, targetPlatform string) (*cdx.BOM, error) {
	scannedBOMs := make([]*cdx.BOM, 0, len(catalogers))
	for _, cataloger := range catalogers {
		dir, cleanup, err := managedinput.MaterializeCatalogerInputs(ctx, step.containerBackend, imageInfo.Name, cataloger, targetPlatform, imageInfo.Env)
		if err != nil {
			return nil, fmt.Errorf("materialize inputs for cataloger %q: %w", cataloger.Name, err)
		}

		bom, installedGems, err := step.scanCatalogerDir(ctx, scanOpts, cataloger, dir, imageInfo.Name, targetPlatform)
		cleanup(ctx)
		if err != nil {
			return nil, err
		}

		// The installed-gemspec cataloger of a directive follows its lock cataloger
		// (see managedinput.ToCatalogers); the lock scan is cut down to the platform
		// variants the image holds.
		if len(installedGems) > 0 && len(scannedBOMs) > 0 {
			managedinput.DropUninstalledGemVariants(scannedBOMs[len(scannedBOMs)-1], installedGems)
		}

		scannedBOMs = append(scannedBOMs, bom)
	}

	// Guarded against an empty catalogers slice, even though the isStapel switch arm only
	// runs when syftScanRequired already established len(catalogers) > 0.
	if len(scannedBOMs) == 0 {
		return cyclonedxutil.NewBOM(), nil
	}

	// On a cross-directive PURL collision, MergeBOMs keeps the first component in merge
	// order (imports before the target), but unions GOST:source_langs from all of them.
	merged, err := cyclonedxutil.MergeBOMs(ctx, scannedBOMs[0], cyclonedxutil.MergeOpts{ImportBOMs: scannedBOMs[1:]})
	if err != nil {
		return nil, fmt.Errorf("union per-directive BOMs: %w", err)
	}

	return merged, nil
}

func (step *sbomStep) scanCatalogerDir(ctx context.Context, scanOpts scanner.ScanOptions, cataloger scanner.Cataloger, dir, imageRef, targetPlatform string) (*cdx.BOM, map[string]string, error) {
	cmd := scanOpts.Commands[0]
	cmd.Catalogers = []scanner.Cataloger{cataloger}
	cmd.SourceType = scanner.SourceTypeDir
	cmd.SourcePath = dir

	perDirectiveOpts := scanOpts
	perDirectiveOpts.Commands = []scanner.ScanCommand{cmd}

	bomJSON, err := step.containerBackend.GenerateSBOM(ctx, perDirectiveOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("generate SBOM for cataloger %q: %w", cataloger.Name, err)
	}

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(bomJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parse scanned BOM for cataloger %q: %w", cataloger.Name, err)
	}

	// A directory source makes syft emit a PURL-less type=file component for each scanned
	// manifest file; drop them so only real packages remain. This is what makes omitting the
	// post-scan source-path filter safe (see SYFT_FILE_METADATA_SELECTION in the docker backend).
	cyclonedxutil.DropSyftSourceFileComponents(bom)

	for i := range lo.FromPtr(bom.Components) {
		gost.SetComponentSourceLangs(ctx, &(*bom.Components)[i], []string{cataloger.SourceLang})
	}

	// The per-directive BOMs are unioned by MergeBOMs, which carries a root edge over
	// only from a BOM werf produced.
	cyclonedxutil.MarkWerfTool(bom, werf.Version)

	installedGems, err := alignInstalledGemVersions(bom, cataloger, dir)
	if err != nil {
		return nil, nil, err
	}

	if err := step.recordDeclaredPackages(ctx, bom, cataloger, dir); err != nil {
		return nil, nil, err
	}

	if config.PackagesDirectiveType(cataloger.Ecosystem) == config.PackagesDirectiveTypeGoMod {
		step.recordGoModuleGraph(ctx, bom, imageRef, cataloger, targetPlatform)
	}

	return bom, installedGems, nil
}

// alignInstalledGemVersions makes the installed-gemspec scan of a ruby directive meet
// the lock scan on the purl: the installed gemspec of a native gem keeps the platform
// apart from the version, the lock writes them as one. The installed versions come
// back so the lock scan can be cut down to them.
func alignInstalledGemVersions(bom *cdx.BOM, cataloger scanner.Cataloger, dir string) (map[string]string, error) {
	if cataloger.Enrichment == nil || cataloger.Enrichment.Kind != scanner.EnrichmentKindGemHome {
		return nil, nil
	}
	installed, err := managedinput.InstalledGemVersions(filepath.Join(dir, filepath.Clean("/"+cataloger.Enrichment.Root)))
	if err != nil {
		return nil, fmt.Errorf("cataloger %q: %w", cataloger.Name, err)
	}
	managedinput.AlignGemVersions(bom, installed)
	return installed, nil
}

// recordGoModuleGraph adds the edges between the Go modules of the directive to the
// BOM. syft's go.mod cataloger reports no relationships, so the graph is read from
// `go mod graph` run inside the built image, where the toolchain and the module cache
// are present by construction: the install command of the directive is `go mod
// download`. The run is offline. A failure — a toolchain or module cache the recipe
// removed after installing, a run that does not finish in time, a foreign target
// platform the host cannot emulate — costs the edges only, not the build: without them
// every module not declared in go.mod is still recorded as indirect.
const goModGraphTimeout = 5 * time.Minute

func (step *sbomStep) recordGoModuleGraph(ctx context.Context, bom *cdx.BOM, imageRef string, cataloger scanner.Cataloger, targetPlatform string) {
	// The directive environment comes first so that the offline settings win over a
	// GOPROXY or GOFLAGS it sets: there is no network in the container to honor them.
	var env []string
	for _, name := range slices.Sorted(maps.Keys(cataloger.Env)) {
		env = append(env, name+"="+cataloger.Env[name])
	}
	env = append(env, "GOFLAGS=-mod=mod", "GOPROXY=off", "GOTOOLCHAIN=local")

	goBin := "go"
	if cataloger.Manager != "" {
		goBin = cataloger.Manager
	}

	runCtx, cancel := context.WithTimeout(ctx, goModGraphTimeout)
	defer cancel()

	graph, err := step.containerBackend.RunCommandInImage(runCtx, imageRef, container_backend.RunCommandInImageOpts{
		CommonOpts: container_backend.CommonOpts{TargetPlatform: targetPlatform},
		Command:    []string{goBin, "mod", "graph"},
		Workdir:    cataloger.Workdir,
		Env:        env,
	})
	if err != nil {
		logboek.Context(ctx).Warn().LogF("WARNING: unable to read the Go module graph of %s in image %q; the SBOM records no dependencies between its modules: %s\n", cataloger.Workdir, imageRef, err)
		return
	}

	edges, err := declared.GoModGraphEdges(bom, graph)
	if err != nil {
		logboek.Context(ctx).Warn().LogF("WARNING: unable to read the Go module graph of %s in image %q; the SBOM records no dependencies between its modules: %s\n", cataloger.Workdir, imageRef, err)
		return
	}
	if len(edges) == 0 {
		return
	}

	bom.Dependencies = lo.ToPtr(append(lo.FromPtr(bom.Dependencies), edges...))
}

// recordDeclaredPackages reads the spec file of the directive out of the scan directory
// and records the packages it declares as direct dependencies of the BOM root, which at
// this point is the scan directory syft reported and later becomes the image. A spec
// werf cannot read — a manifest the manager inside the image accepted — costs the
// declaration only, not the build.
func (step *sbomStep) recordDeclaredPackages(ctx context.Context, bom *cdx.BOM, cataloger scanner.Cataloger, dir string) error {
	ecosystem := config.PackagesDirectiveType(cataloger.Ecosystem)
	if len(cataloger.SourcePaths) == 0 || ecosystem == "" {
		return nil
	}
	specPath := filepath.Join(dir, filepath.Clean("/"+cataloger.SourcePaths[0]))

	spec, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("read spec %s of cataloger %q: %w", cataloger.SourcePaths[0], cataloger.Name, err)
	}

	pkgs, err := declared.ParseSpec(ecosystem, spec)
	if err != nil {
		logboek.Context(ctx).Warn().LogF("WARNING: unable to read the packages %s declares; the SBOM records none of them as the attack surface of the image: %s\n", cataloger.SourcePaths[0], err)
		return nil
	}

	refs, _ := declared.MatchComponents(ctx, bom, ecosystem, pkgs)
	declared.AddRootEdge(bom, refs)

	return nil
}

const sbomArtifactFormatVersion = "17"

// calculateStableChecksum computes the SBOM artifact cache checksum. Together with the
// parent stage digest it forms the cache key: a previously attached SBOM is reused only
// when both match, so the checksum must cover every generation input outside the image
// content. Intentionally excluded: image filesystem content, the syft skip decision and
// the os-pm packages directive (all covered by the parent digest — the packages directive
// feeds the Packages stage digest through the generated install command, and the skip
// decision is derived from catalogers already covered by the scan options checksum),
// gomod patcher inputs (build context changes alter the stage digest), external reference
// enrichment (non-deterministic external data), and generator logic changes (covered by
// sbomArtifactFormatVersion).
func (step *sbomStep) calculateStableChecksum(scanOpts scanner.ScanOptions, mergeOpts cyclonedxutil.MergeOpts, signerIdentity, targetPlatform string, provenance sbomStageProvenance) string {
	return util.Sha256Hash(
		sbomArtifactFormatVersion,
		"scan", scanOpts.Checksum(),
		"merge", mergeOpts.Checksum(),
		"gost_attack_surface", mergeOpts.Gost.AttackSurface.String(),
		"gost_security_function", mergeOpts.Gost.SecurityFunction.String(),
		"signer", signerIdentity,
		"platform", targetPlatform,
		"produced", sbomProvenanceChecksum(provenance),
	)
}

// PropagateArtifactsOptions carries the destinations of a propagation: the final repo
// descriptor of the same image when the build published one, and the cache stages
// storages the stage was placed in.
type PropagateArtifactsOptions struct {
	FinalRepo              string
	FinalDigest            string
	CacheStagesStorageList []storage.StagesStorage
}

// PropagateArtifacts copies the artifacts attached to the image in the repository it
// was built in — its SBOM, VEX and any other attached kind — into the final repo and
// the cache repos. Stages are copied there before the artifacts exist, so the
// artifacts have to catch up separately. The copy runs on every build and is
// idempotent, so a destination holding the image without its artifacts is repaired
// by the next run.
func (step *sbomStep) PropagateArtifacts(ctx context.Context, werfImgName, srcRepo, srcDigest string, opts PropagateArtifactsOptions) error {
	if opts.FinalRepo != "" && opts.FinalRepo != srcRepo {
		if err := logboek.Context(ctx).Info().LogProcess("image %s: Copy attached artifacts into the final repo %s", werfImgName, opts.FinalRepo).DoError(func() error {
			return artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, opts.FinalRepo, opts.FinalDigest, attestation.CopySupersededKeys)
		}); err != nil {
			return fmt.Errorf("copy attached artifacts into final repo %s: %w", opts.FinalRepo, err)
		}
	}

	for _, cache := range opts.CacheStagesStorageList {
		if cache.Address() == storage.LocalStorageAddress || cache.Address() == srcRepo {
			continue
		}
		if err := logboek.Context(ctx).Info().LogProcess("image %s: Copy attached artifacts into cache %s", werfImgName, cache.String()).DoError(func() error {
			return artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, cache.Address(), srcDigest, attestation.CopySupersededKeys)
		}); err != nil {
			logboek.Context(ctx).Warn().LogF("Warning: unable to copy attached artifacts into cache stages storage %s: %s\n", cache.String(), err)
		}
	}

	return nil
}

func (step *sbomStep) GetImageBOM(ctx context.Context, imageName string, imageInfo *image.Info) (*cdx.BOM, error) {
	if imageInfo == nil {
		return nil, fmt.Errorf("image info is nil for %q", imageName)
	}

	bom, err := step.pullImageSbom(ctx, imageName, imageInfo)
	if err != nil {
		return nil, sbomMissingError(imageInfo, err)
	}

	return bom, nil
}

func sbomMissingError(imageInfo *image.Info, err error) error {
	return fmt.Errorf("the image %q must have an SBOM artifact attached; to generate an SBOM for the image, rebuild it with SBOM generation enabled; note: if the image is a multi-platform image built by an older werf version, its SBOM is attached in a legacy platform-ambiguous format and cannot be used — rebuild the image with a newer werf version: %w", imageInfo.Name, err)
}

func (step *sbomStep) pullImageSbom(ctx context.Context, imageName string, imageInfo *image.Info) (*cdx.BOM, error) {
	parentDigest := imageInfo.GetDigest()
	if parentDigest == "" {
		return nil, fmt.Errorf("image digest not available for %q", imageInfo.Name)
	}

	bomJSON, err := sbomImage.PullSBOM(ctx, imageInfo.Repository, parentDigest, imageName)
	if err != nil {
		return nil, fmt.Errorf("pull SBOM for %q: %w", imageName, err)
	}

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(bomJSON)
	if err != nil {
		return nil, fmt.Errorf("parse CycloneDX BOM: %w", err)
	}

	return bom, nil
}

func (step *sbomStep) prepareGostComponents(ctx context.Context, mergeOpts *cyclonedxutil.MergeOpts) error {
	if !mergeOpts.Gost.AttackSurface.IsUndefined() || !mergeOpts.Gost.SecurityFunction.IsUndefined() {
		step.gostWarnOnce.Do(func() {
			logboek.Context(ctx).Default().LogF("Warning: GOST SBOM integration is experimental and its behavior may change in the future\n")
		})
	}

	// Skip GOST validation for base/import BOMs when GOST is not configured.
	// Without this guard, components from patchers (e.g. PM BOMPatcher) that lack GOST
	// properties would fail validation even though GOST is not in use.
	if mergeOpts.Gost.AttackSurface.IsUndefined() && mergeOpts.Gost.SecurityFunction.IsUndefined() {
		return nil
	}

	if mergeOpts.BaseBOM != nil {
		if err := gost.Validate(mergeOpts.BaseBOM); err != nil {
			return fmt.Errorf("base SBOM validation failed (rebuild the base image with the current werf if its SBOM was built by an older one): %w", err)
		}
	}

	for i, externalBOM := range mergeOpts.ImportBOMs {
		if err := gost.Validate(externalBOM); err != nil {
			return fmt.Errorf("external SBOM [%d] validation failed (rebuild the imported image with the current werf if its SBOM was built by an older one): %w", i, err)
		}
	}

	return nil
}
