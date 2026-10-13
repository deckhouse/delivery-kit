package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/werf/werf/v3/pkg/image/journal"
)

func TestMainJournal(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Main image journal")
}

func TestMainJournalProcess(t *testing.T) {
	rawArgs := os.Getenv("WERF_TEST_MAIN_JOURNAL_ARGS")
	if rawArgs == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"werf"}, args...)
	main()
}

var _ = ginkgo.Describe("Journal process lifecycle", func() {
	ginkgo.DescribeTable("does not leave pending markers after command completion", func(args []string, exitCode int, expectedOutput string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		executable, err := os.Executable()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		directory := ginkgo.GinkgoT().TempDir()
		encodedArgs, err := json.Marshal(args)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		command := exec.CommandContext(ctx, executable, "-test.run=^TestMainJournalProcess$")
		command.Env = append(os.Environ(), "WERF_TEST_MAIN_JOURNAL_ARGS="+string(encodedArgs), journal.Env+"="+directory, "WERF_BUILDAH_MODE=docker", "WERF_SELF_INVOCATION_COMMAND=", "WERF_CPU_PROFILE_DIR=")
		output, err := command.CombinedOutput()
		if exitCode == 0 {
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(output))
		} else {
			gomega.Expect(err).To(gomega.HaveOccurred())
		}
		gomega.Expect(command.ProcessState.ExitCode()).To(gomega.Equal(exitCode), string(output))
		gomega.Expect(string(output)).To(gomega.ContainSubstring(expectedOutput))
		gomega.Expect(journal.Check(ctx, directory)).To(gomega.Succeed())
	},
		ginkgo.Entry("kubectl direct exit", []string{"kubectl", "exec"}, 1, "pod, type/name or --filename must be specified"),
		ginkgo.Entry("lazy help command", []string{"help", "build"}, 0, "werf build"),
	)
})

var _ = ginkgo.DescribeTable("marks only commands that can use local images", func(args []string, marked bool) {
	rootCmd := &cobra.Command{Use: "werf"}
	rootCmd.PersistentFlags().Bool("debug", false, "")
	buildCmd := &cobra.Command{Use: "build", RunE: func(*cobra.Command, []string) error { return nil }}
	buildCmd.Flags().String("repo", "", "")
	kubectlCmd := &cobra.Command{Use: "kubectl"}
	kubectlCmd.AddCommand(&cobra.Command{Use: "exec", RunE: func(*cobra.Command, []string) error { return nil }})
	rootCmd.AddCommand(buildCmd, kubectlCmd, &cobra.Command{Use: "kube-run", RunE: func(*cobra.Command, []string) error { return nil }})
	ctx := context.Background()
	directory := ginkgo.GinkgoT().TempDir()
	finish, err := startImageJournal(ctx, rootCmd, args, directory)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	if marked {
		gomega.Expect(journal.Check(ctx, directory)).To(gomega.MatchError(gomega.ContainSubstring("pending-")))
	} else {
		gomega.Expect(journal.Check(ctx, directory)).To(gomega.Succeed())
	}
	gomega.Expect(finish()).To(gomega.Succeed())
	gomega.Expect(journal.Check(ctx, directory)).To(gomega.Succeed())
},
	ginkgo.Entry("kubectl", []string{"kubectl"}, false),
	ginkgo.Entry("kubectl exec", []string{"kubectl", "exec", "pod", "--", "false"}, false),
	ginkgo.Entry("global flag before kubectl", []string{"--debug", "kubectl", "exec", "pod"}, false),
	ginkgo.Entry("build", []string{"build"}, true),
	ginkgo.Entry("kubectl as flag value", []string{"build", "--repo", "kubectl"}, true),
	ginkgo.Entry("kube-run", []string{"kube-run"}, true),
)
