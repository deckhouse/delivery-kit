package build

import (
	"context"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/config"
)

var _ = ginkgo.DescribeTable("Artifact publication in check mode", func(ctx ginkgo.SpecContext, checkOnly bool, run func(*BuildPhase, context.Context) error, expectedError string) {
	graph, err := image.BuildImagesGraph([]*image.Image{{Name: "app", TargetPlatform: "linux/amd64"}})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	tree := &image.ImagesTree{}
	tree.SetImagesGraphForTests(graph)
	storageManager := &checkArtifactsStorageManager{}
	phase := &BuildPhase{
		BasePhase: BasePhase{Conveyor: &Conveyor{
			imagesTree:     tree,
			StorageManager: storageManager,
			werfConfig:     &config.WerfConfig{Meta: &config.Meta{Build: config.MetaBuild{Sbom: &config.MetaBuildSbom{Enable: true}}}},
		}},
		BuildPhaseOptions: BuildPhaseOptions{ShouldBeBuiltMode: checkOnly},
	}

	err = run(phase, ctx)
	if expectedError == "" {
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	} else {
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expectedError)))
	}
	if checkOnly {
		gomega.Expect(storageManager.accesses).To(gomega.BeZero(), "check mode must not enter artifact publication or propagation")
	} else {
		gomega.Expect(storageManager.accesses).To(gomega.Equal(1), "ordinary builds must still enter artifact processing")
	}
},
	ginkgo.Entry("skips SBOM publication", true, (*BuildPhase).convergeSbomByImagesSets, ""),
	ginkgo.Entry("skips VEX publication", true, (*BuildPhase).convergeVexByImagesSets, ""),
	ginkgo.Entry("skips artifact propagation", true, (*BuildPhase).propagateArtifacts, ""),
	ginkgo.Entry("retains ordinary SBOM processing", false, (*BuildPhase).convergeSbomByImagesSets, "SBOM generation requires a container registry"),
	ginkgo.Entry("retains ordinary VEX processing", false, (*BuildPhase).convergeVexByImagesSets, ""),
	ginkgo.Entry("retains ordinary artifact propagation", false, (*BuildPhase).propagateArtifacts, ""),
)
