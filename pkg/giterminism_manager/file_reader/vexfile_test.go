package file_reader_test

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/git_repo"
	"github.com/werf/werf/v3/pkg/giterminism_manager/file_reader"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("ReadVEXFile", func() {
	t := GinkgoT()

	const (
		relPath          = "vex.openvex.json"
		worktreeContent  = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"status":"fixed"}]}`
		committedContent = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`
		commit           = "git head commit"
	)

	var (
		ctx               context.Context
		reader            file_reader.FileReader
		giterminismConfig *MockgiterminismConfig
		gitRepo           *mock.MockGitRepo
	)

	BeforeEach(func() {
		ctrl := gomock.NewController(t)
		ctx = logging.WithLogger(context.Background())

		projectDir := t.TempDir()
		Expect(os.WriteFile(filepath.Join(projectDir, relPath), []byte(worktreeContent), 0o644)).To(Succeed())

		sharedOptions := NewMocksharedOptions(ctrl)
		giterminismConfig = NewMockgiterminismConfig(ctrl)
		gitRepo = mock.NewMockGitRepo(ctrl)

		sharedOptions.EXPECT().ProjectDir().Return(projectDir).AnyTimes()
		sharedOptions.EXPECT().RelativeToGitProjectDir().Return("").AnyTimes()
		sharedOptions.EXPECT().LocalGitRepo().Return(gitRepo).AnyTimes()
		sharedOptions.EXPECT().HeadCommit(gomock.Any()).Return(commit).AnyTimes()
		sharedOptions.EXPECT().LooseGiterminism().Return(false).AnyTimes()
		sharedOptions.EXPECT().Dev().Return(false).AnyTimes()

		reader = file_reader.NewFileReader(sharedOptions)
		reader.SetGiterminismConfig(giterminismConfig)
	})

	It("reads the uncommitted file from the project directory when config.vex.allowUncommitted matches it", func() {
		giterminismConfig.EXPECT().IsUncommittedVexFileAccepted(relPath).Return(true).AnyTimes()

		data, err := reader.ReadVEXFile(ctx, relPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(Equal(worktreeContent))
	})

	It("rejects the uncommitted file when config.vex.allowUncommitted does not match it", func() {
		giterminismConfig.EXPECT().IsUncommittedVexFileAccepted(relPath).Return(false).AnyTimes()
		gitRepo.EXPECT().ValidateStatusResult(gomock.Any(), gomock.Any()).Return(git_repo.UncommittedFilesFoundError{PathList: []string{relPath}})

		_, err := reader.ReadVEXFile(ctx, relPath)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring(relPath)))
		Expect(err).To(MatchError(ContainSubstring("must be committed")))
	})

	It("reads the committed file from the commit when config.vex.allowUncommitted does not match it", func() {
		giterminismConfig.EXPECT().IsUncommittedVexFileAccepted(relPath).Return(false).AnyTimes()
		gitRepo.EXPECT().ValidateStatusResult(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		gitRepo.EXPECT().IsCommitTreeEntryExist(gomock.Any(), commit, relPath).Return(true, nil)
		gitRepo.EXPECT().ResolveAndCheckCommitFilePath(gomock.Any(), commit, relPath, gomock.Any()).Return(relPath, nil)
		gitRepo.EXPECT().ReadCommitFile(gomock.Any(), commit, relPath).Return([]byte(committedContent), nil)

		data, err := reader.ReadVEXFile(ctx, relPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(Equal(committedContent))
	})
})
