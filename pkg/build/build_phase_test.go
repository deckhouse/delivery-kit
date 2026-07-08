package build

import (
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/config"
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
})
