package build

import (
	"fmt"
	"sync"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/config"
)

var _ = ginkgo.Describe("BuildPhase", func() {
	ginkgo.Describe("stage digest mutex lifecycle", func() {
		var (
			digestMutex *sync.Mutex

			simulateCalculateStage func(shouldError bool) (bool, func(), error)
		)

		ginkgo.BeforeEach(func() {
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

		ginkgo.DescribeTable("cleanupFunc handling on error path",
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
				gomega.Expect(err).To(gomega.HaveOccurred())

				acquired := digestMutex.TryLock()
				digestMutex.Unlock()
				gomega.Expect(acquired).To(gomega.Equal(v.expectRelease))
			},
			ginkgo.Entry("buggy: cleanupFunc not called on error path leaks mutex", onImageStageVariant{
				name:          "buggy",
				callCleanup:   false,
				expectRelease: false,
			}),
			ginkgo.Entry("fixed: cleanupFunc called on error path releases mutex", onImageStageVariant{
				name:          "fixed",
				callCleanup:   true,
				expectRelease: true,
			}),
		)
	})

	ginkgo.Describe("calculateDigest", func() {
		ginkgo.It("digest is unchanged when EnableSbom() returns false (backward compatibility)", func(ctx ginkgo.SpecContext) {
			conveyorNoSbom := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestNoSbom, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorNoSbom, calculateDigestOptions{})
			gomega.Expect(err).To(gomega.Succeed())

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
			gomega.Expect(err).To(gomega.Succeed())

			gomega.Expect(digestNoSbom).To(gomega.Equal(digestSbomDisabled))
		})

		ginkgo.It("digest changes when EnableSbom() returns true", func(ctx ginkgo.SpecContext) {
			conveyorDisabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestDisabled, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorDisabled, calculateDigestOptions{})
			gomega.Expect(err).To(gomega.Succeed())

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
			gomega.Expect(err).To(gomega.Succeed())

			gomega.Expect(digestEnabled).NotTo(gomega.Equal(digestDisabled))
		})

		ginkgo.It("digest returns to its original value when EnableSbom() goes back to false", func(ctx ginkgo.SpecContext) {
			conveyorDisabled := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestBaseline, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorDisabled, calculateDigestOptions{})
			gomega.Expect(err).To(gomega.Succeed())

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
			gomega.Expect(err).To(gomega.Succeed())

			gomega.Expect(digestEnabled).NotTo(gomega.Equal(digestBaseline))

			conveyorDisabledAgain := &Conveyor{
				werfConfig: &config.WerfConfig{
					Meta: &config.Meta{},
				},
			}
			digestDisabledAgain, err := calculateDigest(ctx, "test-stage", "test-dependencies", nil, conveyorDisabledAgain, calculateDigestOptions{})
			gomega.Expect(err).To(gomega.Succeed())

			gomega.Expect(digestDisabledAgain).To(gomega.Equal(digestBaseline))
		})
	})
})
