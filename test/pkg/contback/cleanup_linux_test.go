package contback

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Buildah cleanup trace", func() {
	ginkgo.It("reports phase start immediately and records elapsed time and errors", func() {
		var output bytes.Buffer
		done := traceBuildahCleanupPhase(&output, "werf-test-trace", "open storage")
		gomega.Expect(output.String()).To(gomega.ContainSubstring(`project="werf-test-trace"`))
		gomega.Expect(output.String()).To(gomega.ContainSubstring(`phase="open storage" event=start`))
		gomega.Expect(output.String()).NotTo(gomega.ContainSubstring("event=done"))
		done(errors.New("storage unavailable"))
		gomega.Expect(output.String()).To(gomega.MatchRegexp(`phase="open storage" event=done elapsed=\S+ error=storage unavailable`))
	})

	ginkgo.It("streams worker output before cancellation and retains it in the failure", func() {
		if os.Geteuid() == 0 {
			ginkgo.Skip("requires non-root execution to exercise the buildah unshare command")
		}
		dir := ginkgo.GinkgoT().TempDir()
		const marker = "cleanup-worker-started"
		script := "#!/bin/sh\nprintf 'cleanup-worker-started\\n' >&2\nkill -STOP $$\n"
		gomega.Expect(os.WriteFile(filepath.Join(dir, "buildah"), []byte(script), 0o700)).To(gomega.Succeed())
		ginkgo.GinkgoT().Setenv("PATH", dir)
		observer := &cleanupTraceObserver{marker: marker, started: make(chan struct{})}
		ginkgo.GinkgoWriter.TeeTo(observer)
		defer ginkgo.GinkgoWriter.ClearTeeWriters()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- cleanupBuildahProject(ctx, "werf-test-trace", nil)
		}()
		streamed := false
		select {
		case <-observer.started:
			streamed = true
			cancel()
		case <-ctx.Done():
		}
		err := <-result
		gomega.Expect(streamed).To(gomega.BeTrue(), "worker output must arrive before the process exits")
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring(marker))
		gomega.Expect(observer.output.String()).To(gomega.ContainSubstring(`phase="worker process" event=done`))
	})
})
