package common_test

import (
	"fmt"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/utils"
)

var werfRepositoryDir string

func init() {
	var err error
	werfRepositoryDir, err = filepath.Abs("../../../../../")
	if err != nil {
		panic(err)
	}
}

var _ = Describe("context", func() {
	BeforeEach(func(ctx SpecContext) {
		SuiteData.WerfRepoWorktreeDir = filepath.Join(SuiteData.TestDirPath, "werf_repo_worktree")

		utils.RunSucceedCommand(ctx, SuiteData.TestDirPath, "git", "clone", werfRepositoryDir, SuiteData.WerfRepoWorktreeDir)

		utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "checkout", "-b", "integration-context-test", "v1.0.10")
	})

	type entry struct {
		prepareFixturesFunc func(ctx SpecContext)
		expectedDigests     map[string]string
	}

	itBody := func(ctx SpecContext, entry entry) {
		expectedDigest, ok := entry.expectedDigests[runtime.GOARCH]
		if !ok {
			Skip(fmt.Sprintf("skip on %s: no expected digest", runtime.GOARCH))
		}

		entry.prepareFixturesFunc(ctx)

		output, err := utils.RunCommand(
			ctx,
			SuiteData.WerfRepoWorktreeDir,
			SuiteData.WerfBinPath,
			"build", "--debug",
		)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(string(output)).Should(ContainSubstring(expectedDigest))
	}

	_ = DescribeTable("checksum", itBody,
		Entry("base", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "base"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigests: map[string]string{
				"amd64": "57fb876b722ed420f62aaea92cf35665b3ec1f3f8177d7d0ded30e44",
				"arm64": "3798a9fa1e719af302ba0e550dbb94395f1183c6e7973ffd8c2b1a0b",
			},
		}),
		Entry("file from contextAddFile added to context", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_file"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigests: map[string]string{
				"amd64": "75a6e025e44f8f853f3258af6634f28669f7dfa5ccbb5f1b352117be",
				"arm64": "bf82c40575b2cdab81e33bab0f8ee2c17c1efa247abba8cfb57363c2",
			},
		}),
		Entry("symlinks from contextAddFiles added to context as is", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_symlinks"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigests: map[string]string{
				"amd64": "0d2d35d6be53fe942fd99c4fab3c29b245b8f065906f7062946bdcca",
				"arm64": "9d94c61e2e2df1916e46ec51aca6c12a02ba72e6e38155f0e56e0930",
			},
		}),
		Entry("dir from contextAddFiles added to context", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_dir"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigests: map[string]string{
				"amd64": "66f80882c792e392ad17003ec362479e3dda79b8d0b8fd92a70f3af4",
				"arm64": "2569440d2af176823ad56327c6b299e53ad573172395740e2588b77c",
			},
		}),
		Entry("specified files from dir allowed in allowContextAddFiles added to context", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_dir_partially"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigests: map[string]string{
				"amd64": "e03f700a970a62270cbb9843e8bbc3797e70ee3aa0ed3e348da8bf9b",
				"arm64": "6062b687136dd3ea829d7b1dee986eac0564f8191a9452f1bcc3a2d4",
			},
		}),
	)
})
