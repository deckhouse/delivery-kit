package build

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("SBOM stage provenance", func() {
	var configs map[string]*v1.ConfigFile
	var final *image.StageDesc
	var ids []string
	var reads []string
	var readConfig func(context.Context, string) (*v1.ConfigFile, error)

	ginkgo.BeforeEach(func() {
		configs = make(map[string]*v1.ConfigFile)
		ids = nil
		reads = nil
		stages := []stage.StageName{stage.From, stage.BeforeInstall, stage.Packages, stage.Install, stage.DependenciesAfterInstall, stage.Setup, stage.ImageSpec}
		counts := []int{2, 3, 4, 6, 7, 8, 8}
		var parent string
		for i, stageName := range stages {
			digest := strings.Repeat(fmt.Sprintf("%x", i+1), 56)
			id := image.NewStageID(digest, int64(i+1))
			ids = append(ids, id.String())
			record, err := json.Marshal(sbomStageRecord{Stage: stageName, StageDigest: digest, ParentStageID: parent})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			cfg := &v1.ConfigFile{Config: v1.Config{Labels: map[string]string{
				image.WerfSBOMStageLabel: string(record),
				image.WerfParentStageID:  parent,
			}}}
			for j := range counts[i] {
				cfg.RootFS.DiffIDs = append(cfg.RootFS.DiffIDs, v1.Hash{Algorithm: "sha256", Hex: strings.Repeat(fmt.Sprintf("%x", j+1), 64)})
			}
			configs["example.com/stages:"+id.String()] = cfg
			parent = id.String()
			final = &image.StageDesc{StageID: id, Info: &image.Info{Repository: "example.com/stages", Name: "example.com/stages:" + id.String()}}
		}
		readConfig = func(ctx context.Context, ref string) (*v1.ConfigFile, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			reads = append(reads, ref)
			cfg, ok := configs[ref]
			if !ok {
				return nil, fmt.Errorf("config %q missing", ref)
			}
			return cfg.DeepCopy(), nil
		}
	})

	ginkgo.It("recovers eligible ranges from the published final image without intermediate stage objects", func(ctx ginkgo.SpecContext) {
		provenance, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(provenance.Layers).To(gomega.Equal(shippedscope.ProducedLayers{Known: true, Ranges: []shippedscope.ProducedLayerRange{{Start: 4, End: 6}, {Start: 7, End: 8}}}))
		gomega.Expect(provenance.DiffIDs).To(gomega.Equal(configs[final.Info.Name].RootFS.DiffIDs))
		gomega.Expect(provenance.Snapshots).To(gomega.Equal([]sbomStageSnapshot{
			{Stage: stage.From, LayerCount: 2},
			{Stage: stage.BeforeInstall, LayerCount: 3},
			{Stage: stage.Packages, LayerCount: 4},
			{Stage: stage.Install, LayerCount: 6},
			{Stage: stage.DependenciesAfterInstall, LayerCount: 7},
			{Stage: stage.Setup, LayerCount: 8},
			{Stage: stage.ImageSpec, LayerCount: 8},
		}))
		gomega.Expect(reads).To(gomega.HaveLen(len(ids)))
	})

	ginkgo.It("stops at this image's from stage instead of following an internal base", func(ctx ginkgo.SpecContext) {
		from := configs["example.com/stages:"+ids[0]]
		from.Config.Labels[image.WerfParentStageID] = "unavailable-base-1"
		var record sbomStageRecord
		gomega.Expect(json.Unmarshal([]byte(from.Config.Labels[image.WerfSBOMStageLabel]), &record)).To(gomega.Succeed())
		record.ParentStageID = "unavailable-base-1"
		data, err := json.Marshal(record)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		from.Config.Labels[image.WerfSBOMStageLabel] = string(data)
		provenance, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(provenance.Layers.Known).To(gomega.BeTrue())
	})

	ginkgo.DescribeTable("does not infer a complete set from invalid ancestry", func(ctx ginkgo.SpecContext, fault string) {
		ref := "example.com/stages:" + ids[3]
		cfg := configs[ref]
		var record sbomStageRecord
		gomega.Expect(json.Unmarshal([]byte(cfg.Config.Labels[image.WerfSBOMStageLabel]), &record)).To(gomega.Succeed())
		switch fault {
		case "missing ancestor":
			delete(configs, ref)
		case "old cache":
			delete(cfg.Config.Labels, image.WerfSBOMStageLabel)
		case "malformed":
			cfg.Config.Labels[image.WerfSBOMStageLabel] = "{"
		case "inherited label":
			cfg.Config.Labels[image.WerfSBOMStageLabel] = configs["example.com/stages:"+ids[2]].Config.Labels[image.WerfSBOMStageLabel]
		case "recipe mismatch":
			record.StageDigest = strings.Repeat("e", 56)
		case "parent mismatch":
			record.ParentStageID = ids[1]
		case "rewritten layers":
			cfg.RootFS.DiffIDs[0].Hex = strings.Repeat("f", 64)
		case "cycle":
			record.ParentStageID = ids[3]
			cfg.Config.Labels[image.WerfParentStageID] = ids[3]
		case "unknown stage":
			record.Stage = "future-stage"
		}
		if fault == "recipe mismatch" || fault == "parent mismatch" || fault == "cycle" || fault == "unknown stage" {
			data, err := json.Marshal(record)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			cfg.Config.Labels[image.WerfSBOMStageLabel] = string(data)
		}
		provenance, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(provenance.Layers.Known).To(gomega.BeFalse())
		gomega.Expect(provenance.Layers.Ranges).To(gomega.BeEmpty())
		gomega.Expect(provenance.Snapshots).To(gomega.BeEmpty())
	},
		ginkgo.Entry("missing ancestor", "missing ancestor"),
		ginkgo.Entry("old cached image", "old cache"),
		ginkgo.Entry("malformed record", "malformed"),
		ginkgo.Entry("inherited record from an older builder", "inherited label"),
		ginkgo.Entry("recipe digest mismatch", "recipe mismatch"),
		ginkgo.Entry("parent binding mismatch", "parent mismatch"),
		ginkgo.Entry("ELF signing rewrites a prefix", "rewritten layers"),
		ginkgo.Entry("cyclic lineage", "cycle"),
		ginkgo.Entry("unknown stage name", "unknown stage"),
	)

	ginkgo.It("invalidates the provenance checksum when a missing ancestor becomes available", func(ctx ginkgo.SpecContext) {
		complete, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		delete(configs, "example.com/stages:"+ids[3])
		missing, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(sbomProvenanceChecksum(missing)).NotTo(gomega.Equal(sbomProvenanceChecksum(complete)))
	})

	ginkgo.It("binds the checksum to the packages snapshot boundary", func(ctx ginkgo.SpecContext) {
		before, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg := configs["example.com/stages:"+ids[2]]
		var record sbomStageRecord
		gomega.Expect(json.Unmarshal([]byte(cfg.Config.Labels[image.WerfSBOMStageLabel]), &record)).To(gomega.Succeed())
		record.Stage = stage.GitArchive
		data, err := json.Marshal(record)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg.Config.Labels[image.WerfSBOMStageLabel] = string(data)
		after, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(after.DiffIDs).To(gomega.Equal(before.DiffIDs))
		gomega.Expect(after.Layers).To(gomega.Equal(before.Layers))
		gomega.Expect(sbomProvenanceChecksum(after)).NotTo(gomega.Equal(sbomProvenanceChecksum(before)))
	})

	ginkgo.It("preserves the actual dependency backend in snapshots and their checksum", func(ctx ginkgo.SpecContext) {
		before, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg := configs["example.com/stages:"+ids[4]]
		var record sbomStageRecord
		gomega.Expect(json.Unmarshal([]byte(cfg.Config.Labels[image.WerfSBOMStageLabel]), &record)).To(gomega.Succeed())
		record.ImportBackend = "rsync"
		data, err := json.Marshal(record)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg.Config.Labels[image.WerfSBOMStageLabel] = string(data)
		after, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(after.Snapshots[4].ImportBackend).To(gomega.Equal("rsync"))
		gomega.Expect(sbomProvenanceChecksum(after)).NotTo(gomega.Equal(sbomProvenanceChecksum(before)))
	})

	ginkgo.It("recovers from a transient registry error before selecting the SBOM cache key", func(ctx ginkgo.SpecContext) {
		read := readConfig
		failNext := true
		readConfig = func(ctx context.Context, ref string) (*v1.ConfigFile, error) {
			if failNext && ref == "example.com/stages:"+ids[3] {
				failNext = false
				return nil, fmt.Errorf("temporary registry failure")
			}
			return read(ctx, ref)
		}
		failed, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("temporary registry failure")))
		gomega.Expect(failed.Layers.Known).To(gomega.BeFalse())
		recovered, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(recovered.Layers.Known).To(gomega.BeTrue())
		step := &sbomStep{}
		failedKey := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/amd64", failed)
		recoveredKey := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/amd64", recovered)
		gomega.Expect(recoveredKey).NotTo(gomega.Equal(failedKey))
		again, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/amd64", again)).To(gomega.Equal(recoveredKey))
	})

	ginkgo.It("resolves a copied stage chain from another repository", func(ctx ginkgo.SpecContext) {
		for ref, cfg := range maps.Clone(configs) {
			delete(configs, ref)
			configs[strings.Replace(ref, "example.com/stages", "example.com/cache", 1)] = cfg
		}
		final.Info.Repository = "example.com/cache"
		final.Info.Name = "example.com/cache:" + final.StageID.String()
		provenance, err := resolveSBOMStageProvenance(ctx, final, readConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(provenance.Layers.Known).To(gomega.BeTrue())
	})
})
