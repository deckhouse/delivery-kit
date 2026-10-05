package contback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Docker cleanup inspect", func() {
	ginkgo.DescribeTable("retries only transient snapshotter consistency errors", func(mode string, attempts int, succeeds bool) {
		dir := ginkgo.GinkgoT().TempDir()
		script := `#!/bin/sh
printf 'call\n' >> "$INSPECT_CALLS"
if [ "$INSPECT_MODE" = once ] && [ -f "$INSPECT_MARKER" ]; then
  printf '{"Id":"owned"}\n'
  exit 0
fi
: > "$INSPECT_MARKER"
if [ "$INSPECT_MODE" = permanent ]; then
  printf 'Error response from daemon: permission denied\n' >&2
else
  printf 'Error response from daemon: consistency error: data changed during operation, retry\n' >&2
fi
exit 1
`
		gomega.Expect(os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700)).To(gomega.Succeed())
		ginkgo.GinkgoT().Setenv("PATH", dir)
		ginkgo.GinkgoT().Setenv("INSPECT_MODE", mode)
		ginkgo.GinkgoT().Setenv("INSPECT_CALLS", filepath.Join(dir, "calls"))
		ginkgo.GinkgoT().Setenv("INSPECT_MARKER", filepath.Join(dir, "marker"))
		output, err := cleanupDockerInspect(context.Background(), "owned")
		if succeeds {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(output)).To(gomega.ContainSubstring(`"Id":"owned"`))
		} else {
			gomega.Expect(err).To(gomega.HaveOccurred())
		}
		calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.Count(string(calls), "call\n")).To(gomega.Equal(attempts))
	},
		ginkgo.Entry("recovers after concurrent modification", "once", 2, true),
		ginkgo.Entry("bounds repeated concurrent modification", "always", 3, false),
		ginkgo.Entry("does not retry permission errors", "permanent", 1, false),
	)
	ginkgo.It("honors cancellation", func() {
		dir := ginkgo.GinkgoT().TempDir()
		gomega.Expect(os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nexit 42\n"), 0o700)).To(gomega.Succeed())
		ginkgo.GinkgoT().Setenv("PATH", dir)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := cleanupDockerInspect(ctx, "owned")
		gomega.Expect(errors.Is(err, context.Canceled)).To(gomega.BeTrue())
	})
})
