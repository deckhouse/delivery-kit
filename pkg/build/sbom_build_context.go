package build

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/werf/common-go/pkg/util"
	imagePkg "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/git_repo"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	osPm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const producerContextMount = "/.werf/sbom-build-context"

type sbomProducerContext struct {
	directory string
	path      string
	checksum  string
}

func producerDeclarationPresent(img *imagePkg.Image) bool {
	if img.IsDockerfileImage || img.StapelImageConfig == nil || img.StapelImageConfig.ImageBaseConfig().ImageSpec == nil {
		return false
	}
	_, present := img.StapelImageConfig.ImageBaseConfig().ImageSpec.Labels[sbomBuildContextLabel]
	return present
}

func (phase *BuildPhase) producerContext(ctx context.Context, img *imagePkg.Image, stg stage.Interface) (*sbomProducerContext, error) {
	if !phase.Conveyor.EnableSbom() || img.IsDockerfileImage {
		return nil, nil
	}
	if img.StapelImageConfig == nil {
		return nil, nil
	}
	spec := img.StapelImageConfig.ImageBaseConfig().ImageSpec
	if spec == nil {
		return nil, nil
	}
	raw, present := spec.Labels[sbomBuildContextLabel]
	if !present {
		return nil, nil
	}
	declaration, err := parseSBOMBuildContextDeclaration([]byte(raw))
	if err != nil {
		return nil, err
	}
	requested, present := declaration.Stages[stg.Name()]
	if !present {
		return nil, nil
	}
	previous := phase.StagesIterator.GetPrevBuiltImage(img, stg)
	if previous == nil || previous.Image.GetStageDesc() == nil {
		return nil, fmt.Errorf("no-data: producer context at %s has no preceding image", stg.Name())
	}
	previousInfo := previous.Image.GetStageDesc().Info
	if previousInfo == nil || previousInfo.Repository == "" || previousInfo.GetDigest() == "" {
		return nil, fmt.Errorf("no-data: producer context has no pinned preceding image")
	}
	previousName := previousInfo.Repository + "@" + previousInfo.GetDigest()
	backend := phase.Conveyor.ContainerBackend
	if err := backend.Pull(ctx, previousName, container_backend.PullOpts{TargetPlatform: img.TargetPlatform}); err != nil {
		return nil, err
	}
	image, cleanup, err := savedImage(ctx, backend, previousName)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	provenance, err := resolveSBOMStageProvenance(ctx, previous.Image.GetStageDesc(), docker_registry.API().GetRepoImageConfigFile)
	if err != nil {
		return nil, err
	}
	observed, err := collectSBOMSourceSnapshots(ctx, image, provenance)
	if err != nil {
		return nil, err
	}
	if len(observed) == 0 {
		return nil, fmt.Errorf("no-data: producer context has no observed stage snapshots")
	}

	contextSpec := &buildcontext.Context{Version: 1, Platform: img.TargetPlatform, Imports: []buildcontext.Import{}}
	var imports []sbomSourceImportInput
	captured := make(map[string]*sbomSourceImage)
	var identities []string
	for _, requestedPackage := range requested.Packages {
		resolved, err := phase.producerSourceImports(ctx, img, stg.Name(), requestedPackage.SourceImage)
		if err != nil {
			return nil, err
		}
		sourceRef := resolved[0].Reference
		ref, err := name.NewDigest(sourceRef, name.StrictValidation)
		if err != nil {
			return nil, fmt.Errorf("no-data: producer source %s is not pinned: %w", requestedPackage.SourceImage, err)
		}
		sourceConfig, err := nativegate.ReadPinnedOriginalConfig(ctx, sourceRef, requestedPackage.SourcePlatform)
		if err != nil {
			return nil, err
		}
		packet, err := osPm.PacketJSONFromImageLabels(ctx, sourceConfig.Config.Labels, ref.DigestStr())
		if err != nil {
			return nil, fmt.Errorf("producer source %s: %w", requestedPackage.SourceImage, err)
		}
		if err := checkProducerPacket(packet, requestedPackage); err != nil {
			return nil, err
		}
		candidate := sources.Source{Registry: ref.Context().Name(), Platform: requestedPackage.SourcePlatform, Packet: packet}
		contextSpec.Packages = append(contextSpec.Packages, buildcontext.Package{Registry: candidate.Registry, Platform: candidate.Platform, Packet: packet})
		capturedSource, err := captureSBOMSourceImage(ctx, backend, sourceRef, requestedPackage.SourcePlatform)
		if err != nil {
			return nil, err
		}
		capturedSource.Receipt = &sources.Receipt{Version: sources.Version, Sources: []sources.Source{candidate}}
		captured[sourceRef] = capturedSource
		imports = append(imports, resolved...)
		identities = append(identities, sourceRef, string(packet), candidate.Platform)
	}
	assetScope, assetProofs, assetImports, err := phase.producerGoEmbed(ctx, img, stg.Name(), requested.GoEmbed, observed)
	if err != nil {
		return nil, err
	}
	gitOriginals, gitIdentities, err := producerGitSources(ctx, img, requested.GitSources, observed[len(observed)-1].Index)
	if err != nil {
		return nil, err
	}
	prebuiltAssets, prebuiltIdentities, err := phase.producerPrebuiltAssets(ctx, img, stg.Name(), requested.PrebuiltAssets)
	if err != nil {
		return nil, err
	}
	contextSpec.GoEmbed = assetScope
	selected := contextSpec.Packages[*requested.Subject]
	packetIndex, err := json.Marshal(map[string]json.RawMessage{"subject": selected.Packet})
	if err != nil {
		return nil, err
	}
	packets, err := osPm.ParsePmInstalledJSON(packetIndex)
	if err != nil {
		return nil, err
	}
	subject := packets["subject"]
	contextSpec.Subject = shared.BuildComponent{ID: "build-source", Name: subject.Name, Version: subject.Version, Source: shared.BuildSource{Kind: "pm", Locator: selected.Registry, Checksum: subject.Digest}}
	snapshots, err := sbomSourceGateSnapshots(observed, imports, captured)
	if err != nil {
		return nil, err
	}
	// A warm build reuses every preceding stage, so nothing has had to create the
	// conveyor's temp directory before this plan needs a place to live in.
	if err := os.MkdirAll(phase.Conveyor.tmpDir, 0o755); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(phase.Conveyor.tmpDir, "producer-context-")
	if err != nil {
		return nil, err
	}
	path, err := nativegate.MaterializeBuildContext(ctx, contextSpec, observed[len(observed)-1].Index, directory, nativegate.MaterializeBuildContextOptions{ContainerRoot: producerContextMount, Snapshots: snapshots, WebpackSources: requested.WebpackSources, GitOriginals: gitOriginals, PrebuiltAssets: prebuiltAssets})
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	if err := writeAssetProofs(directory, assetProofs); err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	encoded, err := os.ReadFile(filepath.Join(directory, filepath.Base(path)))
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	identity, err := json.Marshal(requested)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	parts := []string{string(identity), string(encoded), sbomProvenanceChecksum(provenance), sbomSourceImportsChecksum(imports)}
	if len(requested.GoEmbed) > 0 {
		parts = append(parts, "go-embed", sbomSourceImportsChecksum(assetImports))
	}
	if len(gitIdentities) > 0 {
		parts = append(append(parts, "git-sources"), gitIdentities...)
	}
	if len(prebuiltIdentities) > 0 {
		parts = append(append(parts, "prebuilt-assets"), prebuiltIdentities...)
	}
	return &sbomProducerContext{directory: directory, path: path, checksum: util.Sha256Hash(append(parts, identities...)...)}, nil
}

// producerGitSources verifies, for every declared Git-backed Node source - a dependency
// the lockfile pins, or the stage's own project - that the git mapping the config adds
// is that very repository at that very commit, and answers the installed files of the
// observed stage that carry the commit's own bytes.
//
// Only a remote mapping is a source anything can be proven about: DK fetched it itself,
// from the url the config names, pinned to the commit the config names. A local
// checkout is whatever the working machine holds - it pins no commit and its origin is
// nobody's statement - so it is refused rather than described.
//
// The repository a locator is held against is the url of the config, not the
// `remote.origin.url` of the mirror DK fetched into: that file is written by whatever
// fetched it, and the recipe is the only thing here the consumer of the SBOM read.
func producerGitSources(ctx context.Context, img *imagePkg.Image, declared []sbomBuildContextGitSource, observed *shippedscope.FileIndex) ([]nativegate.GitOriginal, []string, error) {
	var originals []nativegate.GitOriginal
	var identities []string
	for _, binding := range declared {
		mapping, err := producerGitMapping(img, binding.To)
		if err != nil {
			return nil, nil, err
		}
		repository := mapping.GitRepo()
		if repository == nil {
			return nil, nil, fmt.Errorf("no-data: git mapping %s has no fetched repository", binding.To)
		}
		fetched, remote := repository.(*git_repo.Remote)
		if !remote {
			return nil, nil, fmt.Errorf("invalid: git mapping %s adds a local checkout, which is not a verifiable source: it pins no commit and its origin is unverified", binding.To)
		}
		if mapping.Commit == "" {
			return nil, nil, fmt.Errorf("invalid: git mapping %s is not pinned to a commit", binding.To)
		}
		if binding.project() {
			// The whole repository, placed where the project is: this reads the
			// commit tree from its root, so a mapping adding a part of it elsewhere
			// would name files that are not where it says they are.
			if added := path.Clean("/" + mapping.Add); added != "/" {
				return nil, nil, fmt.Errorf("invalid: git mapping %s adds %s of the project, not the whole repository", binding.To, added)
			}
		}
		original, err := nativegate.VerifyGitOriginal(ctx, nativegate.GitOriginalRequest{
			GitDir:         fetched.GetClonePath(),
			RemoteURL:      fetched.Url,
			Commit:         mapping.Commit,
			Locator:        binding.Locator,
			PackageName:    binding.PackageName,
			PackageVersion: binding.PackageVersion,
			InstalledRoot:  binding.InstalledPath,
			Project:        binding.project(),
		}, observed)
		if err != nil {
			return nil, nil, fmt.Errorf("git source %s: %w", binding.To, err)
		}
		originals = append(originals, *original)
		identities = append(identities, binding.To, fetched.Url, mapping.Commit, original.Component.ID)
	}

	return originals, identities, nil
}

// producerGitMapping names the one mapping of the config that adds the given path. A
// path more than one mapping adds names no single repository and is a refusal.
func producerGitMapping(img *imagePkg.Image, to string) (*stage.GitMapping, error) {
	var found *stage.GitMapping
	for _, stg := range img.GetStages() {
		for _, mapping := range stg.GetGitMappings() {
			if mapping.To != to || mapping == found {
				continue
			}
			if found != nil {
				return nil, fmt.Errorf("invalid: more than one git mapping is added at %s", to)
			}
			found = mapping
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no-data: the config adds no git mapping at %s", to)
	}

	return found, nil
}

func checkProducerPacket(data json.RawMessage, expected sbomBuildContextPackage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for field, wanted := range map[string]string{"name": expected.PackageName, "version": expected.PackageVersion, "type": expected.PackageType} {
		var actual string
		if err := json.Unmarshal(fields[field], &actual); err != nil || actual != wanted {
			return fmt.Errorf("invalid: producer source %s has unexpected %s", expected.SourceImage, field)
		}
	}
	var platforms []string
	if err := json.Unmarshal(fields["arch"], &platforms); err != nil || !slices.Contains(platforms, expected.SourcePlatform) {
		return fmt.Errorf("invalid: producer source %s does not declare %s", expected.SourceImage, expected.SourcePlatform)
	}
	return nil
}

func (phase *BuildPhase) producerSourceImports(ctx context.Context, img *imagePkg.Image, until stage.StageName, source string) ([]sbomSourceImportInput, error) {
	var imports []sbomSourceImportInput
	for _, stg := range img.GetStages() {
		if stg.Name() == until {
			break
		}
		dependencyStage, ok := stg.(interface{ GetImports() []*config.Import })
		if !ok {
			continue
		}
		for _, directive := range dependencyStage.GetImports() {
			if directive.From != source || directive.ExternalImage {
				continue
			}
			resolved, err := phase.resolveImportImage(ctx, img, directive)
			if err != nil {
				return nil, err
			}
			if resolved.info == nil || resolved.info.Repository == "" || resolved.info.GetDigest() == "" {
				return nil, fmt.Errorf("no-data: producer source %s has no resolved dependency digest", source)
			}
			ref, err := name.NewDigest(fmt.Sprintf("%s@%s", resolved.info.Repository, resolved.info.GetDigest()), name.StrictValidation)
			if err != nil {
				return nil, fmt.Errorf("invalid: producer source %s has an invalid resolved reference: %w", source, err)
			}
			imports = append(imports, sbomSourceImportInput{Stage: stg.Name(), Reference: ref.Name(), Scope: nativegate.ImportScope{Backend: phase.sbomImportBackend(), FromPath: directive.Add, ToPath: directive.To, IncludePaths: directive.IncludePaths, ExcludePaths: directive.ExcludePaths}})
		}
	}
	if len(imports) == 0 {
		return nil, fmt.Errorf("no-data: producer source %s is not an earlier explicit import", source)
	}
	for _, item := range imports[1:] {
		if item.Reference != imports[0].Reference {
			return nil, fmt.Errorf("invalid: producer source %s names conflicting dependency results", source)
		}
	}
	return imports, nil
}
