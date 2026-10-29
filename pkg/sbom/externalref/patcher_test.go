package externalref

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewExternalRefPatcher", func() {
	BeforeEach(func() {
		GinkgoT().Setenv(EnvName, "https://refs.example.com/")
		GinkgoT().Setenv(TimeoutEnvName, "")
		GinkgoT().Setenv(RetryTimeoutEnvName, "")
	})

	It("fails without the server URL", func() {
		GinkgoT().Setenv(EnvName, "")
		_, err := NewExternalRefPatcher(NewExternalRefPatcherOptions{})
		Expect(err).To(MatchError(ContainSubstring(EnvName)))
	})

	DescribeTable("rejects an unusable duration",
		func(envName, value string) {
			GinkgoT().Setenv(envName, value)
			_, err := NewExternalRefPatcher(NewExternalRefPatcherOptions{})
			Expect(err).To(MatchError(ContainSubstring(envName)))
			Expect(err).To(MatchError(ContainSubstring(value)))
		},
		Entry("timeout is not a duration", TimeoutEnvName, "ten"),
		Entry("timeout is a bare number", TimeoutEnvName, "10"),
		Entry("timeout is zero", TimeoutEnvName, "0s"),
		Entry("timeout is negative", TimeoutEnvName, "-5s"),
		Entry("retry timeout is not a duration", RetryTimeoutEnvName, "ten"),
		Entry("retry timeout is a bare number", RetryTimeoutEnvName, "30"),
		Entry("retry timeout is zero", RetryTimeoutEnvName, "0s"),
		Entry("retry timeout is negative", RetryTimeoutEnvName, "-5s"),
	)

	DescribeTable("takes the request timeout from the environment",
		func(value string, expected time.Duration) {
			GinkgoT().Setenv(TimeoutEnvName, value)
			cfg, err := serviceConfigFromEnv()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.ServerURL).To(Equal("https://refs.example.com/"))
			Expect(cfg.Timeout).To(Equal(expected))
			Expect(cfg.MaxElapsedTime).To(Equal(defaultMaxElapsedTime))
		},
		Entry("unset falls back to the default", "", defaultServiceTimeout),
		Entry("seconds", "25s", 25*time.Second),
		Entry("minutes", "1m", time.Minute),
		Entry("milliseconds", "1500ms", 1500*time.Millisecond),
	)

	DescribeTable("takes the retry timeout from the environment",
		func(value string, expected time.Duration) {
			GinkgoT().Setenv(RetryTimeoutEnvName, value)
			cfg, err := serviceConfigFromEnv()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.MaxElapsedTime).To(Equal(expected))
			Expect(cfg.Timeout).To(Equal(defaultServiceTimeout))
		},
		Entry("unset falls back to the default", "", defaultMaxElapsedTime),
		Entry("seconds", "45s", 45*time.Second),
		Entry("minutes", "2m", 2*time.Minute),
	)
})
