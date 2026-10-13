package contback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image/journal"
)

var _ = ginkgo.Describe("Docker cleanup inspect", func() {
	ginkgo.It("uses journal IDs without listing and retains foreign aliases", func(ctx ginkgo.SpecContext) {
		dir := ginkgo.GinkgoT().TempDir()
		root := filepath.Join(dir, "journal")
		gomega.Expect(os.MkdirAll(filepath.Join(root, "docker"), 0o700)).To(gomega.Succeed())
		id := strings.Repeat("a", 64)
		gomega.Expect(journal.Record(ctx, filepath.Join(root, "docker"), id)).To(gomega.Succeed())
		script := `#!/bin/sh
if [ "$1" != image ] || [ "$2" != inspect ]; then
  printf 'listing is forbidden\n' >&2
  exit 42
fi
if [ -f "$REMOVED_MARKER" ]; then
  printf '{"Id":"%s","Config":{"Labels":{"werf":"werf-test-journal"}},"RepoTags":["foreign:keep"]}\n' "$IMAGE_ID"
else
  printf '{"Id":"%s","Config":{"Labels":{"werf":"werf-test-journal"}},"RepoTags":["werf-test-journal:owned","foreign:keep"]}\n' "$IMAGE_ID"
fi
`
		gomega.Expect(os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700)).To(gomega.Succeed())
		marker := filepath.Join(dir, "removed")
		ginkgo.GinkgoT().Setenv("PATH", dir)
		ginkgo.GinkgoT().Setenv("REMOVED_MARKER", marker)
		ginkgo.GinkgoT().Setenv("IMAGE_ID", id)
		ginkgo.GinkgoT().Setenv(journal.Env, root)
		var removed []string
		err := cleanupDockerProjectImages(ctx, "werf-test-journal", nil, func(_ context.Context, refs []string) error {
			removed = append(removed, refs...)
			return os.WriteFile(marker, nil, 0o600)
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(removed).To(gomega.Equal([]string{"werf-test-journal:owned"}))
		gomega.Expect(os.Remove(filepath.Join(root, "docker", id))).To(gomega.Succeed())
		gomega.Expect(os.WriteFile(filepath.Join(root, "docker", "invalid"), nil, 0o600)).To(gomega.Succeed())
		err = cleanupDockerProjectImages(ctx, "werf-test-journal", nil, func(context.Context, []string) error { return nil })
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid image journal entry")))
	})

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
