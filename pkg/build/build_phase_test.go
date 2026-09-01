package build

import (
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/image"
	"github.com/werf/werf/v2/pkg/build/signing"
	"github.com/werf/werf/v2/pkg/build/stage"
	"github.com/werf/werf/v2/pkg/config"
	imagePkg "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/pkg/storage/manager"
)

var _ = Describe("BuildPhase", func() {
	Describe("stage digest mutex lifecycle", func() {
		var (
			digestMutex *sync.Mutex

			simulateCalculateStage func(shouldError bool) (bool, func(), error)
		)

		BeforeEach(func() {
			digestMutex = &sync.Mutex{}

			simulateCalculateStage = func(shouldError bool) (bool, func(), error) {
				digestMutex.Lock()
				if shouldError {
					return false, digestMutex.Unlock, fmt.Errorf("simulated error after lock")
				}
				return true, digestMutex.Unlock, nil
			}
		})

		type onImageStageVariant struct {
			name          string
			callCleanup   bool
			expectRelease bool
		}

		DescribeTable("cleanupFunc handling on error path",
			func(v onImageStageVariant) {
				simulateOnImageStage := func(shouldError bool) error {
					var cleanupFunc func()

					err := func() error {
						var err error
						_, cleanupFunc, err = simulateCalculateStage(shouldError)
						if err != nil {
							return err
						}
						return nil
					}()
					if err != nil {
						if v.callCleanup && cleanupFunc != nil {
							cleanupFunc()
						}
						return err
					}

					if cleanupFunc != nil {
						defer cleanupFunc()
					}
					return nil
				}

				err := simulateOnImageStage(true)
				Expect(err).To(HaveOccurred())

				done := make(chan struct{})
				go func() {
					digestMutex.Lock()
					digestMutex.Unlock()
					close(done)
				}()

				if v.expectRelease {
					Eventually(done, 3*time.Second).Should(BeClosed())
				} else {
					Consistently(done, 500*time.Millisecond).ShouldNot(BeClosed())
				}
			},
			Entry("buggy: cleanupFunc not called on error path leaks mutex", onImageStageVariant{
				name:          "buggy",
				callCleanup:   false,
				expectRelease: false,
			}),
			Entry("fixed: cleanupFunc called on error path releases mutex", onImageStageVariant{
				name:          "fixed",
				callCleanup:   true,
				expectRelease: true,
			}),
		)
	})

	Describe("artifact storage validation", func() {
		It("detects VEX configuration", func(ctx SpecContext) {
			img, err := image.NewImage(ctx, "linux/amd64", "app", image.NoBaseImage, image.ImageOptions{
				Vex: &config.Vex{Document: "vex.json"},
			})
			Expect(err).To(Succeed())
			tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
			tree.AppendImageForTests(img)
			phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{
				werfConfig: &config.WerfConfig{Meta: &config.Meta{}},
				imagesTree: tree,
			}}}

			Expect(phase.artifactsEnabled()).To(BeTrue())
		})

		It("rejects enabled artifacts with local-only storage", func() {
			storageManager := &artifactValidationStorageManager{stages: storage.NewLocalStagesStorage(nil)}

			err := validateArtifactStorage(storageManager, true)

			Expect(err).To(MatchError("SBOM or VEX generation requires a container registry (specify --repo), or disable artifact generation"))
		})

		It("allows disabled artifacts with local-only storage", func() {
			storageManager := &artifactValidationStorageManager{stages: storage.NewLocalStagesStorage(nil)}

			Expect(validateArtifactStorage(storageManager, false)).To(Succeed())
		})
	})

	It("skips SBOM convergence when no images were selected", func(ctx SpecContext) {
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{
			werfConfig: &config.WerfConfig{Meta: &config.Meta{Build: config.MetaBuild{Sbom: &config.MetaBuildSbom{Enable: true}}}},
			imagesTree: &image.ImagesTree{},
		}}}

		Expect(phase.convergeSbomByImagesSets(ctx)).To(Succeed())
	})

	It("collects content dependencies from signing mutation stages", func(ctx SpecContext) {
		signer, err := signing.NewSigner(ctx, signing.SignerOptions{})
		Expect(err).To(Succeed())

		baseStageOptions := &stage.BaseStageOptions{TargetPlatform: "linux/amd64"}
		img := &image.Image{}
		img.SetStages([]stage.Interface{
			stage.GenerateVerityAnnotationStage(baseStageOptions),
			stage.GenerateSignStage(baseStageOptions, signing.NewManifestSigningOptions(signer)),
		})

		inputs, err := collectHolisticInputs(ctx, img, nil, nil)
		Expect(err).To(Succeed())
		Expect(inputs).To(HaveLen(2))
		Expect(inputs[0]).To(HavePrefix(string(stage.VerityAnnotation) + ":"))
		Expect(inputs[1]).To(HavePrefix(string(stage.Sign) + ":"))
	})

	Describe("VEX convergence", func() {
		newImage := func(ctx SpecContext, platform string, vex *config.Vex) *image.Image {
			img, err := image.NewImage(ctx, platform, "app", image.NoBaseImage, image.ImageOptions{Vex: vex})
			Expect(err).NotTo(HaveOccurred())
			return img
		}

		newMultiplatformImages := func(ctx SpecContext, vex *config.Vex) []*image.Image {
			images := make([]*image.Image, 2)
			for i, platform := range []string{"linux/amd64", "linux/arm64"} {
				img := newImage(ctx, platform, vex)
				img.SetContentTagDesc(&imagePkg.StageDesc{
					StageID: imagePkg.NewStageID(platform, 1),
					Info:    &imagePkg.Info{},
				})
				images[i] = img
			}
			return images
		}

		newPhaseWithTree := func(multiImg *image.MultiplatformImage) *BuildPhase {
			tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
			tree.SetMultiplatformImage(multiImg)
			return &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: tree}}}
		}

		It("returns an error when a multi-image stage descriptor is unavailable", func(ctx SpecContext) {
			images := newMultiplatformImages(ctx, &config.Vex{Document: "vex.json"})
			phase := newPhaseWithTree(image.NewMultiplatformImage("app", images, 0, 1))

			err := phase.convergeImageVex(ctx, "app", images)

			Expect(err).To(MatchError(`unable to converge VEX for image "app": stage descriptor is unavailable`))
		})

		It("is a no-op for a multi-image without VEX configuration when the stage descriptor is unavailable", func(ctx SpecContext) {
			images := newMultiplatformImages(ctx, nil)
			phase := newPhaseWithTree(image.NewMultiplatformImage("app", images, 0, 1))

			Expect(phase.convergeImageVex(ctx, "app", images)).To(Succeed())
		})

		It("is a no-op for an image without VEX configuration and without a stage descriptor", func(ctx SpecContext) {
			phase := &BuildPhase{}

			Expect(phase.convergeImageVex(ctx, "app", []*image.Image{newImage(ctx, "linux/amd64", nil)})).To(Succeed())
		})

		It("is a no-op for an image with an empty VEX document", func(ctx SpecContext) {
			phase := &BuildPhase{}

			Expect(phase.convergeImageVex(ctx, "app", []*image.Image{newImage(ctx, "linux/amd64", &config.Vex{})})).To(Succeed())
		})

		It("reports an unavailable stage descriptor when VEX is configured", func(ctx SpecContext) {
			phase := &BuildPhase{}

			err := phase.convergeImageVex(ctx, "app", []*image.Image{newImage(ctx, "linux/amd64", &config.Vex{Document: "vex.json"})})
			Expect(err).To(MatchError(ContainSubstring(`unable to converge VEX for image "app": stage descriptor is unavailable`)))
		})
	})

	Describe("last non-empty stage descriptor", func() {
		It("uses the content tag descriptor for a reused image", func() {
			expected := &imagePkg.StageDesc{Info: &imagePkg.Info{Name: "repo:image"}}
			img := &image.Image{}
			img.SetContentTagDesc(expected)

			Expect(img.GetLastNonEmptyStageDesc()).To(BeIdenticalTo(expected))
			Expect(img.GetLastNonEmptyStageImageInfo()).To(BeIdenticalTo(expected.Info))
		})

		It("returns nil when neither a content tag nor a built stage descriptor exists", func() {
			Expect((&image.Image{}).GetLastNonEmptyStageDesc()).To(BeNil())
		})
	})

	Describe("vexStageDesc", func() {
		It("uses the content tag descriptor of a reused single-platform image", func(ctx SpecContext) {
			expected := &imagePkg.StageDesc{Info: &imagePkg.Info{Name: "repo:image"}}
			img, err := image.NewImage(ctx, "linux/amd64", "app", image.NoBaseImage, image.ImageOptions{})
			Expect(err).To(Succeed())
			img.SetContentTagDesc(expected)

			Expect((&BuildPhase{}).vexStageDesc("app", []*image.Image{img})).To(BeIdenticalTo(expected))
		})

		It("returns nil for a single-platform image without any descriptor", func(ctx SpecContext) {
			img, err := image.NewImage(ctx, "linux/amd64", "app", image.NoBaseImage, image.ImageOptions{})
			Expect(err).To(Succeed())

			Expect((&BuildPhase{}).vexStageDesc("app", []*image.Image{img})).To(BeNil())
		})

		It("uses the descriptor of the registered multiplatform image", func(ctx SpecContext) {
			images := make([]*image.Image, 0, 2)
			for _, platform := range []string{"linux/amd64", "linux/arm64"} {
				img, err := image.NewImage(ctx, platform, "app", image.NoBaseImage, image.ImageOptions{})
				Expect(err).To(Succeed())
				img.SetContentTagDesc(&imagePkg.StageDesc{
					StageID: imagePkg.NewStageID("digest-"+platform, 0),
					Info:    &imagePkg.Info{Name: "repo:" + platform},
				})
				images = append(images, img)
			}

			expected := &imagePkg.StageDesc{Info: &imagePkg.Info{Name: "repo:multiplatform"}}
			multiImg := image.NewMultiplatformImage("app", images, 0, 1)
			multiImg.SetStageDesc(expected)

			tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
			tree.SetMultiplatformImage(multiImg)
			phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: tree}}}

			Expect(phase.vexStageDesc("app", images)).To(BeIdenticalTo(expected))
		})

		It("returns nil for a multiplatform image that was never registered", func(ctx SpecContext) {
			images := make([]*image.Image, 0, 2)
			for _, platform := range []string{"linux/amd64", "linux/arm64"} {
				img, err := image.NewImage(ctx, platform, "app", image.NoBaseImage, image.ImageOptions{})
				Expect(err).To(Succeed())
				images = append(images, img)
			}

			phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: image.NewImagesTree(nil, image.ImagesTreeOptions{})}}}

			Expect(phase.vexStageDesc("app", images)).To(BeNil())
		})
	})

	Describe("calculateDigest", func() {
		It("digest is unchanged when EnableSbom() returns false (backward compatibility)", func(ctx SpecContext) {
			conveyorNoSbom := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestNoSbom, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorNoSbom, calculateDigestOptions{})
			Expect(err).To(Succeed())

			conveyorSbomDisabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{
						Build: config.MetaBuild{
							Sbom: &config.MetaBuildSbom{
								Enable: false,
							},
						},
					},
				},
			}
			digestSbomDisabled, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorSbomDisabled, calculateDigestOptions{})
			Expect(err).To(Succeed())

			Expect(digestNoSbom).To(Equal(digestSbomDisabled))
		})

		It("digest changes when EnableSbom() returns true", func(ctx SpecContext) {
			conveyorDisabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestDisabled, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorDisabled, calculateDigestOptions{})
			Expect(err).To(Succeed())

			conveyorEnabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{
						Build: config.MetaBuild{
							Sbom: &config.MetaBuildSbom{
								Enable: true,
							},
						},
					},
				},
			}
			digestEnabled, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorEnabled, calculateDigestOptions{})
			Expect(err).To(Succeed())

			Expect(digestEnabled).NotTo(Equal(digestDisabled))
		})

		It("anchor digest changes when SBOM is enabled", func(ctx SpecContext) {
			disabled := &Conveyor{werfConfig: &config.WerfConfig{Meta: &config.Meta{}}}
			enabled := &Conveyor{werfConfig: &config.WerfConfig{Meta: &config.Meta{Build: config.MetaBuild{Sbom: &config.MetaBuildSbom{Enable: true}}}}}
			opts := calculateDigestOptions{TargetPlatform: "linux/amd64", Anchor: true, HolisticInputs: []string{"from:digest"}}

			disabledDigest, err := calculateDigest(ctx, "anchor", "", nil, disabled, opts)
			Expect(err).To(Succeed())
			enabledDigest, err := calculateDigest(ctx, "anchor", "", nil, enabled, opts)
			Expect(err).To(Succeed())

			Expect(enabledDigest).NotTo(Equal(disabledDigest))
		})

		It("digest returns to its original value when EnableSbom() goes back to false", func(ctx SpecContext) {
			conveyorDisabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestBaseline, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorDisabled, calculateDigestOptions{})
			Expect(err).To(Succeed())

			conveyorEnabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{
						Build: config.MetaBuild{
							Sbom: &config.MetaBuildSbom{
								Enable: true,
							},
						},
					},
				},
			}
			digestEnabled, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorEnabled, calculateDigestOptions{})
			Expect(err).To(Succeed())

			Expect(digestEnabled).NotTo(Equal(digestBaseline))

			conveyorDisabledAgain := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestDisabledAgain, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorDisabledAgain, calculateDigestOptions{})
			Expect(err).To(Succeed())

			Expect(digestDisabledAgain).To(Equal(digestBaseline))
		})
	})

	Describe("finalStageDescForImage", func() {
		It("returns nil for a single-platform image resolved from the cache, without a built stage image", func() {
			phase := &BuildPhase{}

			Expect(finalStageDescForImage(phase, "app", []*image.Image{{}})).To(BeNil())
		})
	})
})

type artifactValidationStorageManager struct {
	manager.StorageManagerInterface
	stages storage.PrimaryStagesStorage
}

func (m *artifactValidationStorageManager) GetStagesStorage() storage.PrimaryStagesStorage {
	return m.stages
}
