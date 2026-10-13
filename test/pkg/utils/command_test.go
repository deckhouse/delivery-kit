package utils

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image/journal"
	"github.com/werf/werf/v3/test/pkg/testresource"
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils Suite")
}

var _ = Describe("RunCommandWithOptions", func() {
	DescribeTable("journals Buildah preparation through command completion", func(operation string, separate, fails bool) {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		journalDir := filepath.Join(dir, "journal")
		Expect(os.MkdirAll(filepath.Join(journalDir, "buildah"), 0o700)).To(Succeed())
		marker := filepath.Join(dir, "executed")
		calls := filepath.Join(dir, "calls")
		id := strings.Repeat("c", 64)
		script := `#!/bin/sh
printf '%s\n' "$*" >> "$HELPER_CALLS"
if [ "$3" = inspect ]; then
  test -f "$HELPER_MARKER" || exit 43
	if [ "$6" = localhost/test:tag ] && [ "$HELPER_EXIT" = 0 ]; then
		printf '{"FromImageID":"%s"}\n' "$HELPER_RETAG_ID"
		exit 0
	fi
  printf '{"FromImageID":"%s"}\n' "$HELPER_IMAGE_ID"
  exit 0
fi
: > "$HELPER_MARKER"
printf '%s\n' "$HELPER_IMAGE_ID"
exit "$HELPER_EXIT"
`
		Expect(os.WriteFile(filepath.Join(dir, "buildah"), []byte(script), 0o700)).To(Succeed())
		GinkgoT().Setenv("PATH", dir)
		GinkgoT().Setenv(journal.Env, journalDir)
		GinkgoT().Setenv("HELPER_MARKER", marker)
		GinkgoT().Setenv("HELPER_CALLS", calls)
		GinkgoT().Setenv("HELPER_IMAGE_ID", id)
		GinkgoT().Setenv("HELPER_RETAG_ID", strings.Repeat("d", 64))
		GinkgoT().Setenv("HELPER_EXIT", "0")
		if fails {
			GinkgoT().Setenv("HELPER_EXIT", "17")
		}
		tracker := testresource.Activate(ctx, "werf-test-helper", "/bin/werf")
		args := []string{"--storage-driver", "overlay", operation, "--tls-verify=false"}
		if operation == "from" {
			args = append(args, "--name", "test-container")
		}
		args = append(args, "localhost/test:tag")
		var err error
		if separate {
			_, _, err = RunCommandWithSeparateStreams(ctx, "/", "buildah", args, RunCommandOptions{})
		} else {
			_, err = RunCommand(ctx, "/", "buildah", args...)
		}
		if fails {
			Expect(err).To(HaveOccurred())
			Expect(journal.Check(ctx, journalDir)).NotTo(Succeed())
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(journal.Check(ctx, journalDir)).To(Succeed())
			_, err = RunCommand(ctx, "/", "buildah", "--storage-driver", "overlay", "run", "test-container", "--", "true")
			Expect(err).NotTo(HaveOccurred())
		}
		ids, err := journal.Read(ctx, filepath.Join(journalDir, "buildah"))
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]string{id}))
		output, err := os.ReadFile(calls)
		Expect(err).NotTo(HaveOccurred())
		kind, ref := "image", id
		if fails {
			ref = "localhost/test:tag"
		}
		if operation == "from" {
			kind, ref = "container", "test-container"
		}
		if operation == "pull" && !fails {
			Expect(string(output)).NotTo(ContainSubstring("inspect"))
		} else {
			Expect(string(output)).To(ContainSubstring("inspect --type " + kind + " " + ref))
		}
		snapshot, err := tracker.Finish(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(snapshot.Backends).To(Equal([]string{"buildah"}))
	}, Entry("pull", "pull", false, false), Entry("from with separate streams", "from", true, false), Entry("failed pull retains incomplete marker", "pull", false, true))

	It("drains stderr while command writes", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		output, err := RunCommandWithOptions(ctx, "", "sh", []string{"-c", "dd if=/dev/zero bs=1024 count=128 >&2; printf done"}, RunCommandOptions{})

		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring("done"))
	})
})
