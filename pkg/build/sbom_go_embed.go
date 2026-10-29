package build

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/jsonstrict"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

type sbomAssetProof struct {
	name string
	body []byte
}

func (phase *BuildPhase) producerGoEmbed(ctx context.Context, img *image.Image, until stage.StageName, declared []sbomBuildContextGoEmbed, snapshots []sbomSourceSnapshot) (*buildcontext.GoEmbedScope, []sbomAssetProof, []sbomSourceImportInput, error) {
	if len(declared) == 0 {
		return nil, nil, nil, nil
	}
	if len(snapshots) == 0 {
		return nil, nil, nil, fmt.Errorf("no-data: asset bindings have no observed stage snapshots")
	}
	result := &buildcontext.GoEmbedScope{Version: 1, Bindings: []buildcontext.GoEmbedBinding{}}
	var proofs []sbomAssetProof
	var imports []sbomSourceImportInput
	final := snapshots[len(snapshots)-1].Index
	for i, requested := range declared {
		resolved, err := phase.producerSourceImports(ctx, img, until, requested.SourceImage)
		if err != nil {
			return nil, nil, nil, err
		}
		reference := resolved[0].Reference
		source, err := captureSBOMSourceImagePaths(ctx, phase.Conveyor.ContainerBackend, reference, img.TargetPlatform, []string{sources.DefaultPath, requested.ProofPath})
		if err != nil {
			return nil, nil, nil, err
		}
		for name := requested.ProofPath; name != "/"; name = path.Dir(name) {
			if _, linked := source.Index.Symlinks[name]; linked {
				return nil, nil, nil, fmt.Errorf("invalid: asset proof path %s traverses a symlink", requested.ProofPath)
			}
		}
		if _, directory := source.Index.Directories[requested.ProofPath]; directory {
			return nil, nil, nil, fmt.Errorf("invalid: asset proof %s is a directory", requested.ProofPath)
		}
		body, exists := source.Bodies[requested.ProofPath]
		if !exists {
			return nil, nil, nil, fmt.Errorf("no-data: source %s has no asset proof at %s", requested.SourceImage, requested.ProofPath)
		}
		if _, exists := source.Index.Directories[requested.SourceRoot]; !exists {
			return nil, nil, nil, fmt.Errorf("no-data: asset directory %s is not in the source image", requested.SourceRoot)
		}
		paths, err := assetProofPaths(body, requested.SourceRoot)
		if err != nil {
			return nil, nil, nil, err
		}
		var files []string
		for _, item := range paths {
			name := path.Join(requested.SourceRoot, item)
			if _, found := source.Index.Files[name]; found {
				files = append(files, name)
			}
		}
		mapping := make(map[string]string)
		matchedRoot := false
		for _, input := range resolved {
			from := path.Clean(input.Scope.FromPath)
			if from != "/" && requested.SourceRoot != from && !strings.HasPrefix(requested.SourceRoot, from+"/") {
				continue
			}
			at := slices.IndexFunc(snapshots, func(snapshot sbomSourceSnapshot) bool { return snapshot.Stage == input.Stage })
			if at < 1 {
				return nil, nil, nil, fmt.Errorf("no-data: asset import has no preceding %s snapshot", input.Stage)
			}
			scope := input.Scope
			backend := snapshots[at].ImportBackend
			switch backend {
			case "copy-recurse":
				scope.Backend = nativegate.ImportBackendCopyRecurse
			case "rsync":
				scope.Backend = nativegate.ImportBackendRsync
			default:
				return nil, nil, nil, fmt.Errorf("no-data: asset import %s has no known recorded backend", input.Stage)
			}
			root, err := nativegate.ProjectImportedDirectory(ctx, source.Index, snapshots[at-1].Index, snapshots[at].Index, scope, requested.SourceRoot)
			if err != nil {
				return nil, nil, nil, err
			}
			if root != requested.TargetRoot {
				continue
			}
			matchedRoot = true
			projected, err := nativegate.ProjectImportedFiles(ctx, source.Index, snapshots[at-1].Index, snapshots[at].Index, scope, files)
			if err != nil {
				return nil, nil, nil, err
			}
			for from, to := range projected {
				if final.Files[to] != source.Index.Files[from] {
					continue
				}
				relative := strings.TrimPrefix(from, strings.TrimSuffix(requested.SourceRoot, "/")+"/")
				if prior, found := mapping[to]; found && prior != relative {
					return nil, nil, nil, fmt.Errorf("invalid: conflicting asset imports at %s", to)
				}
				mapping[to] = relative
			}
		}
		if !matchedRoot {
			return nil, nil, nil, fmt.Errorf("invalid: asset source %s has no import from %s to %s", requested.SourceImage, requested.SourceRoot, requested.TargetRoot)
		}
		digest := sha256.Sum256(body)
		name := fmt.Sprintf("proofs/%d.json", i)
		binding := buildcontext.GoEmbedBinding{
			SourceStageRef: reference, SourceRoot: requested.SourceRoot, TargetRoot: requested.TargetRoot,
			Proof: buildcontext.GoEmbedProofRef{Version: 1, Path: path.Join(producerContextMount, name), SHA256: "sha256:" + hex.EncodeToString(digest[:])}, Assets: []buildcontext.GoEmbedAssetMapping{},
		}
		for _, target := range slices.Sorted(maps.Keys(mapping)) {
			binding.Assets = append(binding.Assets, buildcontext.GoEmbedAssetMapping{SourcePath: mapping[target], Path: target})
		}
		result.Bindings = append(result.Bindings, binding)
		proofs = append(proofs, sbomAssetProof{name: name, body: body})
		imports = append(imports, resolved...)
	}
	if err := result.Validate(); err != nil {
		return nil, nil, nil, err
	}
	return result, proofs, imports, nil
}

// Only paths are projected here. The producer's shared validator checks the entire
// original proof, including unselected rows, before any Go cache lookup.
func assetProofPaths(data []byte, root string) ([]string, error) {
	var document map[string]json.RawMessage
	if err := jsonstrict.Decode(data, &document); err != nil {
		return nil, fmt.Errorf("invalid: asset proof JSON: %w", err)
	}
	if document == nil {
		return nil, fmt.Errorf("invalid: asset proof must be an object")
	}
	for key := range document {
		for _, canonical := range []string{"version", "sourceRoot", "assets"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return nil, fmt.Errorf("invalid: noncanonical asset proof field %s", key)
			}
		}
	}
	for _, key := range []string{"version", "sourceRoot", "assets"} {
		value, exists := document[key]
		if !exists {
			return nil, fmt.Errorf("no-data: asset proof has no %s", key)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("invalid: asset proof %s is null", key)
		}
	}
	var version int
	if err := json.Unmarshal(document["version"], &version); err != nil {
		return nil, fmt.Errorf("invalid: asset proof version: %w", err)
	}
	if version != 1 {
		return nil, fmt.Errorf("unsupported: asset proof version %d", version)
	}
	var sourceRoot string
	if err := json.Unmarshal(document["sourceRoot"], &sourceRoot); err != nil || sourceRoot != root {
		return nil, fmt.Errorf("invalid: asset proof source root does not match %s", root)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(document["assets"], &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("invalid: asset proof requires an assets array")
	}
	var result []string
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry != nil {
			for key := range entry {
				if key != "path" && strings.EqualFold(key, "path") {
					return nil, fmt.Errorf("invalid: noncanonical asset path field %s", key)
				}
			}
			if _, exists := entry["path"]; !exists {
				return nil, fmt.Errorf("no-data: asset proof row has no path")
			}
		}
		var name string
		if entry == nil || bytes.Equal(entry["path"], []byte("null")) || json.Unmarshal(entry["path"], &name) != nil || name == "" || path.IsAbs(name) || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
			return nil, fmt.Errorf("invalid: asset proof requires clean relative asset paths")
		}
		if seen[name] {
			return nil, fmt.Errorf("invalid: duplicate asset proof path %s", name)
		}
		seen[name] = true
		result = append(result, name)
	}
	return result, nil
}

func writeAssetProofs(directory string, proofs []sbomAssetProof) error {
	if len(proofs) == 0 {
		return nil
	}
	if err := os.Mkdir(filepath.Join(directory, "proofs"), 0o755); err != nil {
		return err
	}
	for _, proof := range proofs {
		file, err := os.OpenFile(filepath.Join(directory, proof.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(proof.body)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
