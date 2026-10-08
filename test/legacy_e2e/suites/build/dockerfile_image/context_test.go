package common_test

import (
	"path/filepath"

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
		expectedDigest      string
	}

	itBody := func(ctx SpecContext, entry entry) {
		entry.prepareFixturesFunc(ctx)

		output, err := utils.RunCommand(
			ctx,
			SuiteData.WerfRepoWorktreeDir,
			SuiteData.WerfBinPath,
			"build", "--debug",
		)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(string(output)).Should(ContainSubstring(entry.expectedDigest))
	}

	_ = DescribeTable("checksum", itBody,
		Entry("base", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "base"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigest: "054ee525c2f9571a739a25346fcf64f0d733e44af5286869ad3fc3ac",
		}),
		Entry("file from contextAddFile added to context", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_file"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigest: "b34be0dc016d3cf55b119a095caa23e947052f1b00a93360d3aad0d6",
		}),
		Entry("symlinks from contextAddFiles added to context as is", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_symlinks"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigest: "18f45dd0f2477fb75ecd3264a0b2b1a1ca996605d79bf05347a7c828",
		}),
		Entry("dir from contextAddFiles added to context", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_dir"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigest: "a84f9419502e8de2e7e4ba2e4a6c54ec280d880179c9d9a8a289a032",
		}),
		Entry("specified files from dir allowed in allowContextAddFiles added to context", entry{
			prepareFixturesFunc: func(ctx SpecContext) {
				utils.CopyIn(utils.FixturePath("context", "context_add_dir_partially"), SuiteData.WerfRepoWorktreeDir)

				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "add", "werf.yaml", "werf-giterminism.yaml", ".dockerignore", "Dockerfile")
				utils.RunSucceedCommand(ctx, SuiteData.WerfRepoWorktreeDir, "git", "commit", "-m", "+")
			},
			expectedDigest: "bf638a6545ad26fefdb55fdbd94cb36affd7c00b4bde4daa8c0ae941",
		}),
	)
})
