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
	})

	It("fails without the server URL", func() {
		GinkgoT().Setenv(EnvName, "")
		_, err := NewExternalRefPatcher(NewExternalRefPatcherOptions{})
		Expect(err).To(MatchError(ContainSubstring(EnvName)))
	})

	DescribeTable("rejects an unusable timeout",
		func(value string) {
			GinkgoT().Setenv(TimeoutEnvName, value)
			_, err := NewExternalRefPatcher(NewExternalRefPatcherOptions{})
			Expect(err).To(MatchError(ContainSubstring(TimeoutEnvName)))
			Expect(err).To(MatchError(ContainSubstring(value)))
		},
		Entry("not a duration", "ten"),
		Entry("bare number", "10"),
		Entry("zero", "0s"),
		Entry("negative", "-5s"),
	)

	DescribeTable("takes the request timeout from the environment",
		func(value string, expected time.Duration) {
			GinkgoT().Setenv(TimeoutEnvName, value)
			cfg, err := serviceConfigFromEnv()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.ServerURL).To(Equal("https://refs.example.com/"))
			Expect(cfg.Timeout).To(Equal(expected))
		},
		Entry("unset falls back to the default", "", defaultServiceTimeout),
		Entry("seconds", "25s", 25*time.Second),
		Entry("minutes", "1m", time.Minute),
		Entry("milliseconds", "1500ms", 1500*time.Millisecond),
	)
})
