package build

import (
	"context"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("SBOM source snapshots", func() {
	var img v1.Image
	var provenance sbomStageProvenance
	var receipt string

	ginkgo.BeforeEach(func() {
		receipt = `{"version":1,"sources":[{"registry":"registry.example.test/pkg","packet":{"name":"x","version":"1","arch":["linux/amd64"],"digest":"sha256:` + strings.Repeat("a", 64) + `","opaque":9007199254740993},"platform":"linux/amd64"}]}`
		img = sourceSnapshotImage(
			[]sourceSnapshotFile{{Name: "already", Body: "equal"}},
			[]sourceSnapshotFile{{Name: strings.TrimPrefix(sources.DefaultPath, "/"), Body: receipt}, {Name: "usr/lib/foo", Body: "equal"}},
			[]sourceSnapshotFile{{Name: "var/lib/pm/.wh.sbom-sources.json"}, {Name: "usr/lib/.wh.foo"}, {Name: "opt/foo", Body: "equal"}},
		)
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		provenance = sbomStageProvenance{
			Layers:  shippedscope.ProducedLayers{Known: true},
			DiffIDs: cfg.RootFS.DiffIDs,
			Snapshots: []sbomStageSnapshot{
				{Stage: stage.From, LayerCount: 1},
				{Stage: stage.Packages, LayerCount: 2},
				{Stage: stage.Install, LayerCount: 3},
			},
		}
	})

	ginkgo.It("captures packages sources before a shell deletes the receipt and relocates bytes", func(ctx ginkgo.SpecContext) {
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(snapshots).To(gomega.HaveLen(3))
		gomega.Expect(snapshots[0].Receipt).To(gomega.BeNil())
		gomega.Expect(snapshots[0].ReceiptStatus).To(gomega.Equal("no-data"))
		gomega.Expect(snapshots[1].Stage).To(gomega.Equal(stage.Packages))
		gomega.Expect(snapshots[1].LayerCount).To(gomega.Equal(2))
		gomega.Expect(snapshots[1].ReceiptStatus).To(gomega.Equal("present"))
		gomega.Expect(snapshots[1].Receipt.Sources).To(gomega.HaveLen(1))
		gomega.Expect(string(snapshots[1].Receipt.Sources[0].Packet)).To(gomega.ContainSubstring(`"opaque":9007199254740993`))
		gomega.Expect(snapshots[1].Index.Files).To(gomega.HaveKey("/usr/lib/foo"))
		gomega.Expect(snapshots[1].Index.Files["/already"]).To(gomega.Equal(snapshots[0].Index.Files["/already"]))
		gomega.Expect(snapshots[2].Receipt).To(gomega.BeNil())
		gomega.Expect(snapshots[2].ReceiptStatus).To(gomega.Equal("no-data"))
		gomega.Expect(snapshots[2].Index.Files).NotTo(gomega.HaveKey("/usr/lib/foo"))
		gomega.Expect(snapshots[2].Index.Files["/opt/foo"]).To(gomega.Equal(snapshots[1].Index.Files["/usr/lib/foo"]))
	})

	ginkgo.It("keeps the recorded backend while capturing the actual rootfs", func(ctx ginkgo.SpecContext) {
		provenance.Snapshots[2].Stage = stage.DependenciesAfterInstall
		provenance.Snapshots[2].ImportBackend = "rsync"
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(snapshots[2].ImportBackend).To(gomega.Equal("rsync"))
	})

	ginkgo.It("distinguishes an explicit empty source list from an absent receipt", func(ctx ginkgo.SpecContext) {
		img = sourceSnapshotImage([]sourceSnapshotFile{{Name: strings.TrimPrefix(sources.DefaultPath, "/"), Body: `{"version":1,"sources":[]}`}})
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		provenance.DiffIDs = cfg.RootFS.DiffIDs
		provenance.Snapshots = []sbomStageSnapshot{{Stage: stage.From}, {Stage: stage.Packages, LayerCount: 1}}
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(snapshots[0].Receipt).To(gomega.BeNil())
		gomega.Expect(snapshots[1].Receipt).NotTo(gomega.BeNil())
		gomega.Expect(snapshots[1].ReceiptStatus).To(gomega.Equal("present"))
		gomega.Expect(snapshots[1].Receipt.Sources).To(gomega.BeEmpty())
	})

	ginkgo.DescribeTable("does not return partial snapshots for an unusable receipt", func(ctx ginkgo.SpecContext, body, status string) {
		img = sourceSnapshotImage([]sourceSnapshotFile{{Name: strings.TrimPrefix(sources.DefaultPath, "/"), Body: body}})
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		provenance.DiffIDs = cfg.RootFS.DiffIDs
		provenance.Snapshots = []sbomStageSnapshot{{Stage: stage.From}, {Stage: stage.Packages, LayerCount: 1}}
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("stage packages: " + status)))
		gomega.Expect(snapshots).To(gomega.BeNil())
	},
		ginkgo.Entry("empty file", "", "no-data"),
		ginkgo.Entry("missing sources", `{"version":1}`, "no-data"),
		ginkgo.Entry("null sources", `{"version":1,"sources":null}`, "no-data"),
		ginkgo.Entry("malformed JSON", `{`, "invalid"),
		ginkgo.Entry("duplicate fields", `{"version":1,"version":1,"sources":[]}`, "invalid"),
		ginkgo.Entry("future schema", `{"version":2,"sources":[]}`, "unsupported"),
	)

	ginkgo.It("does not treat a symlink receipt as an absent source list", func(ctx ginkgo.SpecContext) {
		img = sourceSnapshotImage([]sourceSnapshotFile{{Name: strings.TrimPrefix(sources.DefaultPath, "/"), Target: "/missing"}})
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		provenance.DiffIDs = cfg.RootFS.DiffIDs
		provenance.Snapshots = []sbomStageSnapshot{{Stage: stage.From}, {Stage: stage.Packages, LayerCount: 1}}
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is a symlink")))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})

	ginkgo.DescribeTable("rejects incomplete or reordered boundaries", func(ctx ginkgo.SpecContext, fault string) {
		switch fault {
		case "unknown":
			provenance.Layers.Known = false
		case "empty":
			provenance.Snapshots = nil
		case "missing from":
			provenance.Snapshots = provenance.Snapshots[1:]
		case "missing final":
			provenance.Snapshots = provenance.Snapshots[:2]
		case "reordered":
			provenance.Snapshots[0].LayerCount = 3
		}
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(snapshots).To(gomega.BeNil())
	},
		ginkgo.Entry("unknown provenance", "unknown"),
		ginkgo.Entry("no checkpoints", "empty"),
		ginkgo.Entry("missing base", "missing from"),
		ginkgo.Entry("missing final image", "missing final"),
		ginkgo.Entry("nonmonotonic layer counts", "reordered"),
	)

	ginkgo.It("propagates cancellation without partial source evidence", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		snapshots, err := collectSBOMSourceSnapshots(ctx, img, provenance)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(context.Canceled.Error())))
		gomega.Expect(snapshots).To(gomega.BeNil())
	})
})
