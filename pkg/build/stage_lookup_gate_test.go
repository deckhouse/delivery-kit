package build

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/storage/synchronization/lock_manager"
)

var _ = ginkgo.Describe("Stage lookup strictness gate", func() {
	newStageDesc := func(name string) *imagePkg.StageDesc {
		return &imagePkg.StageDesc{
			StageID: imagePkg.NewStageID("digest0", 1),
			Info: &imagePkg.Info{
				Name:   name,
				Labels: map[string]string{imagePkg.WerfStageContentDigestLabel: "content"},
			},
		}
	}

	newPhaseWithImage := func(shouldBeBuiltMode bool, inPrimary, inSecondary imagePkg.StageDescSet) (*BuildPhase, *buildImage.Image, *anchorLookupStorageManager) {
		storageManager := &anchorLookupStorageManager{
			primaryStagesStorage:   &anchorPrimaryStagesStorage{},
			secondaryStagesStorage: &fakeStagesStorage{},
			inPrimary:              inPrimary,
			inSecondary:            inSecondary,
		}
		phase := newTestBuildPhase(storageManager, nil)
		phase.ShouldBeBuiltMode = shouldBeBuiltMode

		ctx := ginkgo.GinkgoT().Context()
		srv, _ := newPublicationLockServer()
		lockManager, err := lock_manager.NewHttp(ctx, srv.URL, "shared-client-id")
		gomega.Expect(err).To(gomega.Succeed())
		phase.Conveyor.StorageLockManager = lockManager

		img := newTestImage("image0", true)
		img.Conveyor = phase.Conveyor
		img.ForceTargetPlatformLogging = true
		img.SetAnchorDigest("anchor0")
		anchor := stage.NewBaseStage(stage.ImageSpec, &stage.BaseStageOptions{ImageName: img.Name})
		anchor.SetContentAnchor(true)
		img.SetStages([]stage.Interface{anchor})
		phase.Conveyor.imagesTree.SetImagesGraphForTests(newTestImagesGraph(img))
		phase.StagesIterator = NewStagesIterator(phase.Conveyor)

		_, err = phase.BeforeImageStages(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		return phase, img, storageManager
	}

	buildImageStages := func(shouldBeBuiltMode bool, inPrimary, inSecondary imagePkg.StageDescSet) (*buildImage.Image, *anchorLookupStorageManager) {
		_, img, storageManager := newPhaseWithImage(shouldBeBuiltMode, inPrimary, inSecondary)
		return img, storageManager
	}

	ginkgo.It("uses only the cached primary lookup in normal build mode", func() {
		_, storageManager := buildImageStages(false, imagePkg.NewStageDescSet(newStageDesc("repo:published")), imagePkg.NewStageDescSet())
		gomega.Expect(storageManager.cachedPrimaryLookups).To(gomega.BeNumerically(">", 0))
		gomega.Expect(storageManager.recentPrimaryLookups).To(gomega.BeZero())
		gomega.Expect(storageManager.strictPrimaryLookups).To(gomega.BeZero())
	})

	ginkgo.It("uses the strict primary lookup in should-be-built mode", func() {
		_, storageManager := buildImageStages(true, imagePkg.NewStageDescSet(newStageDesc("repo:published")), imagePkg.NewStageDescSet())
		gomega.Expect(storageManager.strictPrimaryLookups).To(gomega.BeNumerically(">", 0))
		gomega.Expect(storageManager.recentPrimaryLookups).To(gomega.BeZero())
	})

	ginkgo.It("uses only the cached secondary lookup in normal build mode", func() {
		_, storageManager := buildImageStages(false, imagePkg.NewStageDescSet(), imagePkg.NewStageDescSet())
		gomega.Expect(storageManager.cachedSecondaryLookups).To(gomega.BeNumerically(">", 0))
		gomega.Expect(storageManager.secondaryLookups).To(gomega.BeZero())
	})

	ginkgo.It("looks up no secondary storage in should-be-built mode", func() {
		// Promoting a secondary stage copies it into the primary storage, so a check that images
		// are built must not read a secondary storage at all, strictly or otherwise.
		_, storageManager := buildImageStages(true, imagePkg.NewStageDescSet(), imagePkg.NewStageDescSet())
		gomega.Expect(storageManager.secondaryLookups).To(gomega.BeZero())
		gomega.Expect(storageManager.cachedSecondaryLookups).To(gomega.BeZero())
	})

	ginkgo.It("keeps the anchor prepass on cached primary lookups even in should-be-built mode", func(ctx ginkgo.SpecContext) {
		phase, _, storageManager := newPhaseWithImage(true, imagePkg.NewStageDescSet(), imagePkg.NewStageDescSet())
		storageManager.strictPrimaryLookups = 0
		storageManager.secondaryLookups = 0
		storageManager.cachedSecondaryLookups = 0

		gomega.Expect(phase.resolveAvailableContentAnchors(ctx)).To(gomega.Succeed())
		gomega.Expect(storageManager.strictPrimaryLookups).To(gomega.BeZero())
		gomega.Expect(storageManager.cachedPrimaryLookups).To(gomega.BeNumerically(">", 0))
		gomega.Expect(storageManager.secondaryLookups).To(gomega.BeZero())
		gomega.Expect(storageManager.cachedSecondaryLookups).To(gomega.BeZero())
	})

	ginkgo.It("promotes a cached secondary hit after reconciling against a fresh primary lookup", func() {
		promoted := newStageDesc("secondary:promoted")
		img, storageManager := buildImageStages(false, imagePkg.NewStageDescSet(), imagePkg.NewStageDescSet(promoted))

		gomega.Expect(storageManager.cachedSecondaryLookups).To(gomega.Equal(1))
		gomega.Expect(storageManager.secondaryLookups).To(gomega.BeZero())
		gomega.Expect(storageManager.freshPrimaryLookups).To(gomega.Equal(1))
		gomega.Expect(storageManager.copiedFromSecondary).To(gomega.Equal(1))
		gomega.Expect(img.GetContentTagDesc()).To(gomega.Equal(promoted))
		gomega.Expect(img.AnchorReused).To(gomega.BeTrue())
	})
})
