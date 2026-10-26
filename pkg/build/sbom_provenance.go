package build

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type sbomStageRecord struct {
	Stage         stage.StageName `json:"stage"`
	StageDigest   string          `json:"stageDigest"`
	ParentStageID string          `json:"parentStageID"`
}

type sbomStageProvenance struct {
	Layers  shippedscope.ProducedLayers
	Sources shippedscope.ProducedLayers
	DiffIDs []v1.Hash
}

func resolveSBOMStageProvenance(ctx context.Context, final *image.StageDesc, readConfig func(context.Context, string) (*v1.ConfigFile, error)) (sbomStageProvenance, error) {
	unknown := sbomStageProvenance{}
	if final == nil || final.StageID == nil || final.Info == nil || final.Info.Repository == "" {
		return unknown, fmt.Errorf("resolve SBOM stages: final stage descriptor is incomplete")
	}

	ref := final.Info.RepoDigest
	if ref == "" {
		ref = final.Info.Name
	}
	current, err := readConfig(ctx, ref)
	if err != nil {
		return unknown, fmt.Errorf("read SBOM stage config %q: %w", ref, err)
	}
	if current == nil {
		return unknown, fmt.Errorf("read SBOM stage config %q: empty config", ref)
	}

	result := sbomStageProvenance{DiffIDs: slices.Clone(current.RootFS.DiffIDs)}
	id := final.StageID.String()
	digest := final.StageID.Digest
	seen := make(map[string]bool)
	stages := []stage.StageName{
		stage.From, stage.BeforeInstall, stage.DependenciesBeforeInstall, stage.GitArchive,
		stage.Packages, stage.Install, stage.DependenciesAfterInstall, stage.BeforeSetup,
		stage.DependenciesBeforeSetup, stage.Setup, stage.DependenciesAfterSetup,
		stage.GitCache, stage.GitLatestPatch, stage.ImageSpec, stage.VerityAnnotation, stage.Sign,
	}
	previousPosition := len(stages)
	for {
		if err := ctx.Err(); err != nil {
			return unknown, err
		}
		if seen[id] {
			return unknown, fmt.Errorf("resolve SBOM stages: cyclic parent %q", id)
		}
		seen[id] = true

		var record sbomStageRecord
		if err := json.Unmarshal([]byte(current.Config.Labels[image.WerfSBOMStageLabel]), &record); err != nil {
			return unknown, fmt.Errorf("read SBOM stage record %q: %w", id, err)
		}
		if record.StageDigest != digest || record.ParentStageID != current.Config.Labels[image.WerfParentStageID] {
			return unknown, fmt.Errorf("resolve SBOM stages: record does not belong to stage %q", id)
		}
		position := slices.Index(stages, record.Stage)
		if position < 0 || position >= previousPosition {
			return unknown, fmt.Errorf("resolve SBOM stages: unexpected stage %q at %q", record.Stage, id)
		}
		previousPosition = position
		if record.Stage == stage.From {
			result.Layers.Known = true
			result.Sources.Known = true
			slices.Reverse(result.Sources.Ranges)
			slices.Reverse(result.Layers.Ranges)

			return result, nil
		}

		parentDigest, timestamp, ok := strings.Cut(record.ParentStageID, "-")
		if !ok || parentDigest == "" {
			return unknown, fmt.Errorf("resolve SBOM stages: invalid parent %q", record.ParentStageID)
		}
		if _, err := hex.DecodeString(parentDigest); err != nil {
			return unknown, fmt.Errorf("read SBOM parent digest %q: %w", parentDigest, err)
		}
		if ts, err := strconv.ParseInt(timestamp, 10, 64); err != nil || ts <= 0 {
			return unknown, fmt.Errorf("resolve SBOM stages: invalid parent timestamp %q", timestamp)
		}
		parentRef, err := name.NewTag(final.Info.Repository + ":" + record.ParentStageID)
		if err != nil {
			return unknown, fmt.Errorf("parse SBOM parent reference: %w", err)
		}
		parent, err := readConfig(ctx, parentRef.Name())
		if err != nil {
			return unknown, fmt.Errorf("read SBOM parent config %q: %w", parentRef.Name(), err)
		}
		if parent == nil {
			return unknown, fmt.Errorf("read SBOM parent config %q: empty config", parentRef.Name())
		}
		parentLayers := parent.RootFS.DiffIDs
		currentLayers := current.RootFS.DiffIDs
		if len(parentLayers) > len(currentLayers) || !slices.Equal(parentLayers, currentLayers[:len(parentLayers)]) {
			return unknown, fmt.Errorf("resolve SBOM stages: parent layers are not a prefix of stage %q", id)
		}
		if record.Stage == stage.GitArchive || record.Stage == stage.GitCache || record.Stage == stage.GitLatestPatch {
			result.Sources.Ranges = append(result.Sources.Ranges, shippedscope.ProducedLayerRange{Start: len(parentLayers), End: len(currentLayers)})
		}
		if record.Stage == stage.Install || record.Stage == stage.BeforeSetup || record.Stage == stage.Setup {
			result.Layers.Ranges = append(result.Layers.Ranges, shippedscope.ProducedLayerRange{Start: len(parentLayers), End: len(currentLayers)})
		}

		current = parent
		id = record.ParentStageID
		digest = parentDigest
	}
}

func sbomProvenanceChecksum(provenance sbomStageProvenance) string {
	parts := []string{strconv.FormatBool(provenance.Layers.Known), "diffids"}
	for _, diffID := range provenance.DiffIDs {
		parts = append(parts, diffID.String())
	}
	parts = append(parts, "ranges")
	for _, layerRange := range provenance.Layers.Ranges {
		parts = append(parts, fmt.Sprintf("%d:%d", layerRange.Start, layerRange.End))
	}

	return util.Sha256Hash(parts...)
}
