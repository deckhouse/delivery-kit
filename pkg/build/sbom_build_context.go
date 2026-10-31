package build

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

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
	"github.com/werf/werf/v3/pkg/sbom/webpackcollector"
)

// werfPrivateMountRoot is where werf mounts the scratch a checked stage is built
// against. Nothing under it is in the image the stage produces.
const werfPrivateMountRoot = "/.werf"

const producerContextMount = werfPrivateMountRoot + "/sbom-build-context"

// webpackCollectorMount is where the collector this werf carries is mounted for a
// stage that compiles a checked Webpack build.
const webpackCollectorMount = werfPrivateMountRoot + "/sbom-webpack"

type sbomProducerContext struct {
	directory string
	path      string
	checksum  string
	// webpack is the collector tree the stage's Webpack build is instrumented with,
	// present exactly for a stage that declared one.
	webpack *sbomWebpackCollector
}

// sbomWebpackCollector is the extracted collector of one stage: the scratch it was
// unpacked into and the environment the build is run with.
type sbomWebpackCollector struct {
	directory string
	env       map[string]string
}

// remove releases every scratch directory this producer context owns.
func (input *sbomProducerContext) remove() error {
	directories := []string{input.directory}
	if input.webpack != nil {
		directories = append(directories, input.webpack.directory)
	}
	var errs []error
	for _, directory := range directories {
		errs = append(errs, os.RemoveAll(directory))
	}

	return errors.Join(errs...)
}

// extractWebpackCollector is the collector delivery of a checked Webpack stage. It is a
// variable so that the specs of the stage wiring can hand the phase a tree of their own:
// the collector this werf really carries is only there in a build tagged to embed it.
var extractWebpackCollector = webpackcollector.Extract

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
	opened, installedPackets, err := producerInstalledPackets(observed, requested.InstalledPackets)
	if err != nil {
		return nil, err
	}
	for _, source := range opened {
		contextSpec.Packages = append(contextSpec.Packages, buildcontext.Package{Registry: source.Registry, Platform: source.Platform, Packet: source.Packet})
		identities = append(identities, "pm-installed", source.Registry, string(source.Packet), source.Platform)
	}
	assetScope, assetProofs, assetImports, err := phase.producerGoEmbed(ctx, img, stg.Name(), requested.GoEmbed, observed)
	if err != nil {
		return nil, err
	}
	gitOriginals, gitIdentities, err := producerGitSources(ctx, img, requested.GitSources, gitMirrorAllowlist(declaration.GitMirrors), observed[len(observed)-1].Index)
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
	path, err := nativegate.MaterializeBuildContext(ctx, contextSpec, observed[len(observed)-1].Index, directory, nativegate.MaterializeBuildContextOptions{ContainerRoot: producerContextMount, Snapshots: snapshots, WebpackSources: requested.WebpackSources, GitOriginals: gitOriginals, InstalledPackets: installedPackets, PrebuiltAssets: prebuiltAssets})
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
	input := &sbomProducerContext{directory: directory, path: path}
	if requested.WebpackSources {
		collector, digest, err := phase.webpackCollector(requested, previousInfo.Env)
		if err != nil {
			_ = input.remove()
			return nil, err
		}
		input.webpack = collector
		// The collector is a producer of this evidence like the compiler is: a werf
		// carrying another one instruments the build differently, so the stage it
		// builds is another stage.
		parts = append(parts, "webpack-collector", digest)
		for _, key := range slices.Sorted(maps.Keys(collector.env)) {
			parts = append(parts, key, collector.env[key])
		}
	}
	input.checksum = util.Sha256Hash(append(parts, identities...)...)

	return input, nil
}

// webpackCollector unpacks the collector this werf carries into scratch of its own and
// states what the stage's Webpack build is run with.
//
// Only the NODE_OPTIONS the preceding image already states is visible here, and the
// collector is appended to it. A recipe exporting NODE_OPTIONS inside the stage's own
// shell commands replaces this value instead, and has to append to it itself; this is
// no silent omission - the proof is then never written and the consuming obligation
// refuses the assets for want of evidence.
func (phase *BuildPhase) webpackCollector(requested sbomBuildContextStage, imageEnv []string) (*sbomWebpackCollector, string, error) {
	directory, err := os.MkdirTemp(phase.Conveyor.tmpDir, "webpack-collector-")
	if err != nil {
		return nil, "", err
	}
	digest, err := extractWebpackCollector(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, "", fmt.Errorf("webpack collector: %w", err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		_ = os.RemoveAll(directory)
		return nil, "", err
	}

	options := "--require " + webpackCollectorMount + "/activate.cjs"
	if existing := imageEnvironmentValue(imageEnv, "NODE_OPTIONS"); existing != "" {
		options = existing + " " + options
	}
	env := map[string]string{
		"NODE_OPTIONS":           options,
		"DK_SBOM_WEBPACK_CONFIG": requested.WebpackConfig,
		"DK_SBOM_WEBPACK_PROOF":  requested.WebpackProof,
		"DK_SBOM_YARN_CACHE":     requested.YarnCache,
	}
	if esbuild := requested.Esbuild; esbuild != nil {
		env["DK_SBOM_ESBUILD_VERSION"] = esbuild.Version
		env["DK_SBOM_ESBUILD_LOADER_VERSION"] = esbuild.LoaderVersion
		env["DK_SBOM_ESBUILD_ENTRY"] = esbuild.Entry
		env["DK_SBOM_ESBUILD_BINARY"] = esbuild.Binary
		env["DK_SBOM_ESBUILD_LOADER"] = esbuild.Loader
		env["DK_SBOM_ESBUILD_RUNTIME_SOURCE"] = esbuild.RuntimeSource
		// The esbuild client runs the executable this very declaration names, not
		// whichever one its own install directory holds.
		env["ESBUILD_BINARY_PATH"] = esbuild.Binary
	}

	return &sbomWebpackCollector{directory: directory, env: env}, digest, nil
}

// imageEnvironmentValue is what an image config states for one variable. A config
// repeating one keeps the last, which is the value its containers are given.
func imageEnvironmentValue(env []string, name string) string {
	value := ""
	for _, entry := range env {
		if rest, found := strings.CutPrefix(entry, name+"="); found {
			value = rest
		}
	}

	return value
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
// fetched it, and the recipe is the only thing here the consumer of the SBOM read. A
// url the config's own mirror allowlist states to serve the pinned repository is that
// repository; everything the allowlist does not name is a different one, as before.
func producerGitSources(ctx context.Context, img *imagePkg.Image, declared []sbomBuildContextGitSource, mirrors []nativegate.GitMirror, observed *shippedscope.FileIndex) ([]nativegate.GitOriginal, []string, error) {
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
			Mirrors:        mirrors,
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

// producerInstalledPackets names, for every packet identity the stage declares it
// installed, the one entry of the install receipt the built stages actually carry that
// opens it. Where that packet came from is the receipt's answer, never the recipe's: the
// declaration carries no registry, and a receipt opening the identity none or twice is a
// refusal rather than a choice.
func producerInstalledPackets(observed []sbomSourceSnapshot, declared []sbomBuildContextInstalledPacket) ([]sources.Source, []nativegate.InstalledPacket, error) {
	if len(declared) == 0 {
		return nil, nil, nil
	}
	var receipt *sources.Receipt
	boundaries := 0
	for _, snapshot := range observed {
		if snapshot.Stage != stage.Packages {
			continue
		}
		receipt, boundaries = snapshot.Receipt, boundaries+1
	}
	if boundaries != 1 {
		return nil, nil, fmt.Errorf("no-data: %d package install boundaries among the built stages, need exactly one", boundaries)
	}

	opened := make([]sources.Source, 0, len(declared))
	installed := make([]nativegate.InstalledPacket, 0, len(declared))
	for _, packet := range declared {
		wanted := nativegate.InstalledPacket{
			Name: packet.PackageName, Version: packet.PackageVersion,
			Type: packet.PackageType, Platform: packet.SourcePlatform, Files: packet.Files,
		}
		source, err := nativegate.SelectInstalledPacket(receipt, wanted)
		if err != nil {
			return nil, nil, err
		}
		opened = append(opened, source)
		installed = append(installed, wanted)
	}

	return opened, installed, nil
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
			// The backend here is a placeholder the gate snapshots replace with the
			// one the importing stage recorded; nothing reads it before that.
			imports = append(imports, sbomSourceImportInput{Stage: stg.Name(), Reference: ref.Name(), Bootstrap: resolved.bootstrap, Scope: nativegate.ImportScope{Backend: phase.sbomImportBackend(), FromPath: directive.Add, ToPath: directive.To, IncludePaths: directive.IncludePaths, ExcludePaths: directive.ExcludePaths}})
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
