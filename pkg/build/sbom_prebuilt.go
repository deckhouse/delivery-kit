package build

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/jsonstrict"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

// prebuiltProofVersion is the proof version the Node collector writes, and the only one
// a delivered composition is read out of.
const prebuiltProofVersion = 1

// producerPrebuiltAssets reads, for every declared prebuilt binding, the composition the
// instrumented rebuild of that dependency proved for the one file this stage installs.
//
// The trust boundary is the producer, the same one goEmbed stands on: the proof is taken
// to be the output of a DK producer stage of this very build, and this code does not
// re-derive what that stage observed. What it does establish is that the proof is that
// stage's: the rebuild is an image of this werf.yaml whose own stage declaration asks for
// the collector, it is an earlier explicit import of this image pinned by digest, the
// proof is read out of that image's own bytes, and the row delivered is a described row
// of a proof version this build knows.
//
// The equality between the delivered digest and the file installed here is checked where
// the originals manifest is written when that file is an import of this context, and by
// the collector itself when the project's own package manager installed it.
func (phase *BuildPhase) producerPrebuiltAssets(ctx context.Context, img *image.Image, until stage.StageName, declared []sbomBuildContextPrebuilt) ([]nativegate.PrebuiltAsset, []string, error) {
	if len(declared) == 0 {
		return nil, nil, nil
	}
	var assets []nativegate.PrebuiltAsset
	var identities []string
	for _, requested := range declared {
		if err := phase.checkPrebuiltSourceDeclaration(requested.SourceImage); err != nil {
			return nil, nil, err
		}
		resolved, err := phase.producerSourceImports(ctx, img, until, requested.SourceImage)
		if err != nil {
			return nil, nil, err
		}
		reference := resolved[0].Reference
		source, err := captureSBOMSourceImagePaths(ctx, phase.Conveyor.ContainerBackend, reference, img.TargetPlatform, []string{sources.DefaultPath, requested.ProofPath})
		if err != nil {
			return nil, nil, err
		}
		for name := requested.ProofPath; name != "/"; name = path.Dir(name) {
			if _, linked := source.Index.Symlinks[name]; linked {
				return nil, nil, fmt.Errorf("invalid: prebuilt proof path %s traverses a symlink", requested.ProofPath)
			}
		}
		if _, directory := source.Index.Directories[requested.ProofPath]; directory {
			return nil, nil, fmt.Errorf("invalid: prebuilt proof %s is a directory", requested.ProofPath)
		}
		body, exists := source.Bodies[requested.ProofPath]
		if !exists {
			return nil, nil, fmt.Errorf("no-data: source %s has no prebuilt proof at %s", requested.SourceImage, requested.ProofPath)
		}
		asset, err := prebuiltAssetFromProof(body, requested.AssetPath, requested.InstalledPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", requested.SourceImage, err)
		}
		assets = append(assets, asset)
		identities = append(identities, reference, requested.ProofPath, requested.AssetPath, requested.InstalledPath, asset.SHA256)
	}

	return assets, identities, nil
}

// checkPrebuiltSourceDeclaration holds the named rebuild to the recipe of this very
// werf.yaml: an image of this config whose own producer declaration asks for the webpack
// collector. An image that was never declared to run it cannot have written a collector
// proof, whatever a file in it is called.
func (phase *BuildPhase) checkPrebuiltSourceDeclaration(sourceImage string) error {
	return checkPrebuiltSourceDeclaration(phase.Conveyor.werfConfig.GetImage(sourceImage), sourceImage)
}

func checkPrebuiltSourceDeclaration(configured config.ImageInterface, sourceImage string) error {
	if configured == nil || reflect.ValueOf(configured).IsNil() {
		return fmt.Errorf("no-data: prebuilt source %s is no image of this configuration", sourceImage)
	}
	stapel, ok := configured.(config.StapelImageInterface)
	if !ok {
		return fmt.Errorf("no-data: prebuilt source %s is no stapel image", sourceImage)
	}
	spec := stapel.ImageBaseConfig().ImageSpec
	if spec == nil {
		return fmt.Errorf("no-data: prebuilt source %s declares no producer context", sourceImage)
	}
	raw, present := spec.Labels[sbomBuildContextLabel]
	if !present {
		return fmt.Errorf("no-data: prebuilt source %s declares no producer context", sourceImage)
	}
	declaration, err := parseSBOMBuildContextDeclaration([]byte(raw))
	if err != nil {
		return fmt.Errorf("prebuilt source %s: %w", sourceImage, err)
	}
	for _, declared := range declaration.Stages {
		if declared.WebpackSources {
			return nil
		}
	}

	return fmt.Errorf("no-data: prebuilt source %s declares no stage that runs the webpack collector", sourceImage)
}

// prebuiltAssetFromProof reads one row of a collector proof as the composition of the
// file it names. A row that is anything other than a described asset delivers nothing:
// the collector states what it could not account for, and an unaccounted asset is exactly
// what must not be claimed here.
func prebuiltAssetFromProof(data []byte, assetPath, installedPath string) (nativegate.PrebuiltAsset, error) {
	var document map[string]json.RawMessage
	if err := jsonstrict.Decode(data, &document); err != nil {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof JSON: %w", err)
	}
	if document == nil {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof must be an object")
	}
	for key := range document {
		switch key {
		case "version", "sourceRoot", "assets":
		default:
			// A member this build does not know may be the one that qualifies
			// what the rest of the document says.
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: unknown prebuilt proof member %s", key)
		}
	}
	for _, key := range []string{"version", "assets"} {
		value, exists := document[key]
		if !exists {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("no-data: prebuilt proof has no %s", key)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof %s is null", key)
		}
	}
	var version int
	if err := json.Unmarshal(document["version"], &version); err != nil {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof version: %w", err)
	}
	if version != prebuiltProofVersion {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("unsupported: prebuilt proof version %d", version)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(document["assets"], &raw); err != nil || raw == nil {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof requires an assets array")
	}
	// Each row is read strictly in its own right: a field this build does not
	// know, or one stated twice, is a proof it cannot read rather than one to
	// take the parts it recognizes out of.
	var found *prebuiltProofRow
	for _, body := range raw {
		var row prebuiltProofRow
		if err := jsonstrict.Decode(body, &row); err != nil {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof row: %w", err)
		}
		if row.Path != assetPath {
			continue
		}
		if found != nil {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt proof states %s twice", assetPath)
		}
		found = &row
	}
	if found == nil {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("no-data: prebuilt proof states no asset %s", assetPath)
	}
	if found.Status != "present" {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("no-data: prebuilt asset %s is %s in its own proof", assetPath, found.Status)
	}
	if !prebuiltDigest(found.SHA256) {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s carries no sha256 digest", assetPath)
	}
	if found.Size <= 0 {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s is described as empty", assetPath)
	}

	// The row's own account has to hold together before it is carried anywhere: an
	// included component it does not state, or an input claimed by a component it does
	// not state, is a composition this build cannot read.
	known := make(map[string]bool, len(found.Components))
	components := make([]shared.BuildComponent, 0, len(found.Components))
	for _, component := range found.Components {
		if component.ID == "" || known[component.ID] {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s states an unnamed or repeated component", assetPath)
		}
		known[component.ID] = true
		components = append(components, component)
	}
	if len(components) == 0 {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("no-data: prebuilt asset %s states no components", assetPath)
	}
	// The row's own two accounts of what is in the asset have to be the same
	// account: a component stated but not included is carried by nothing, and an
	// included component that is not stated is a name without an identity.
	included := make(map[string]bool, len(found.IncludedComponents))
	for _, id := range found.IncludedComponents {
		if !known[id] {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s includes the unstated component %s", assetPath, id)
		}
		included[id] = true
	}
	for _, component := range components {
		if !included[component.ID] {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s states the component %s it does not include", assetPath, component.ID)
		}
	}
	if len(found.Inputs) == 0 {
		return nativegate.PrebuiltAsset{}, fmt.Errorf("no-data: prebuilt asset %s states no inputs", assetPath)
	}
	claimed := make(map[string]bool, len(components))
	inputs := make([]nativegate.PrebuiltInput, 0, len(found.Inputs))
	for _, input := range found.Inputs {
		if input.Path == "" || !prebuiltDigest(input.SHA256) {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s states an unnamed or undigested input", assetPath)
		}
		if len(input.Components) == 0 {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s states input %s claimed by no component", assetPath, input.Path)
		}
		for _, id := range input.Components {
			if !known[id] {
				return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s states input %s claimed by the unstated component %s", assetPath, input.Path, id)
			}
			claimed[id] = true
		}
		inputs = append(inputs, nativegate.PrebuiltInput{Path: input.Path, SHA256: input.SHA256, Components: input.Components})
	}
	for _, component := range components {
		if !claimed[component.ID] {
			return nativegate.PrebuiltAsset{}, fmt.Errorf("invalid: prebuilt asset %s states the component %s no input is claimed by", assetPath, component.ID)
		}
	}

	return nativegate.PrebuiltAsset{InstalledPath: installedPath, SHA256: found.SHA256, Components: components, Inputs: inputs}, nil
}

// prebuiltProofRow is the collector's asset row, read for what a delivery needs of it.
type prebuiltProofRow struct {
	Path               string                  `json:"path"`
	SHA256             string                  `json:"sha256"`
	Size               int                     `json:"size"`
	Status             string                  `json:"status"`
	IncludedComponents []string                `json:"includedComponents"`
	Components         []shared.BuildComponent `json:"components"`
	Inputs             []prebuiltProofInput    `json:"inputs"`
	Tools              []json.RawMessage       `json:"tools"`
	Reason             string                  `json:"reason,omitempty"`
}

type prebuiltProofInput struct {
	Kind        string   `json:"kind"`
	Path        string   `json:"path"`
	SHA256      string   `json:"sha256"`
	Components  []string `json:"components"`
	Disposition string   `json:"disposition"`
}

func prebuiltDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}

	return true
}
