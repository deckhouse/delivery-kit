package build

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("SBOM provenance with actual Stapel stage order", func() {
	ginkgo.It("accepts the full mapper-generated chain and excludes dependency stages", func(ctx ginkgo.SpecContext) {
		img := newSBOMStageOrderImage(ctx)
		configs := make(map[string]*v1.ConfigFile)
		var final *image.StageDesc
		var parentID string
		var diffIDs []v1.Hash
		var stageNames []stage.StageName
		var expectedRanges []shippedscope.ProducedLayerRange
		for i, stg := range img.GetStages() {
			stageName := stg.Name()
			stageNames = append(stageNames, stageName)
			if stageName == stage.Install || stageName == stage.BeforeSetup || stageName == stage.Setup {
				expectedRanges = append(expectedRanges, shippedscope.ProducedLayerRange{Start: i, End: i + 1})
			}
			digest := fmt.Sprintf("%056x", i+1)
			stageID := image.NewStageID(digest, int64(i+1))
			record, err := json.Marshal(sbomStageRecord{Stage: stageName, StageDigest: digest, ParentStageID: parentID})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			diffIDs = append(diffIDs, v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%064x", i+1)})
			cfg := &v1.ConfigFile{Config: v1.Config{Labels: map[string]string{
				image.WerfSBOMStageLabel: string(record), image.WerfParentStageID: parentID,
			}}}
			cfg.RootFS.DiffIDs = append([]v1.Hash{}, diffIDs...)
			ref := "example.com/stages:" + stageID.String()
			configs[ref] = cfg
			parentID = stageID.String()
			final = &image.StageDesc{StageID: stageID, Info: &image.Info{Repository: "example.com/stages", Name: ref}}
		}
		gomega.Expect(stageNames).To(gomega.ConsistOf(
			stage.From, stage.BeforeInstall, stage.DependenciesBeforeInstall, stage.GitArchive,
			stage.Packages, stage.Install, stage.DependenciesAfterInstall, stage.BeforeSetup,
			stage.DependenciesBeforeSetup, stage.Setup, stage.DependenciesAfterSetup,
			stage.GitCache, stage.GitLatestPatch, stage.ImageSpec, stage.VerityAnnotation, stage.Sign,
		))
		provenance, err := resolveSBOMStageProvenance(ctx, final, func(_ context.Context, ref string) (*v1.ConfigFile, error) {
			cfg, ok := configs[ref]
			if !ok {
				return nil, fmt.Errorf("config %q missing", ref)
			}
			return cfg.DeepCopy(), nil
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(provenance.Layers.Known).To(gomega.BeTrue())
		gomega.Expect(provenance.Layers.Ranges).To(gomega.Equal(expectedRanges))
		gomega.Expect(provenance.Layers.Ranges).To(gomega.HaveLen(3))
	})
})
