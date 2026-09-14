package utils

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils Suite")
}

var _ = Describe("RunCommandWithOptions", func() {
	It("drains stderr while command writes", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		output, err := RunCommandWithOptions(ctx, "", "sh", []string{"-c", "dd if=/dev/zero bs=1024 count=128 >&2; printf done"}, RunCommandOptions{})

		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring("done"))
	})

	It("forwards output to GinkgoWriter while the command is still running", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tee := gbytes.NewBuffer()
		GinkgoWriter.TeeTo(tee)
		DeferCleanup(GinkgoWriter.ClearTeeWriters)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			_, _ = RunCommandWithOptions(ctx, "", "sh", []string{"-c", "printf early; sleep 3"}, RunCommandOptions{})
		}()

		Eventually(tee, 2*time.Second).Should(gbytes.Say("early"))
		Expect(done).NotTo(BeClosed())

		Eventually(done, 5*time.Second).Should(BeClosed())
	})
})
