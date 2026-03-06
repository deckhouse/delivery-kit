package gomod

import (
	"context"

	cdxgo "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/git_repo"
	"github.com/werf/werf/v2/pkg/logging"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("ResolveUnknownVersions", func() {
	DescribeTable("ResolveUnknownVersions",
		func(ctx context.Context, expectError bool, expectedErrorMsg string, setupMocks func(ctx context.Context, gitRepo *mock.MockGitRepo) (git_repo.GitRepo, string, string, *cdxgo.BOM), verify func(result *cdxgo.BOM, err error)) {
			ctx = logging.WithLogger(ctx)

			var gitRepo git_repo.GitRepo
			var commit string
			var imageContext string
			var bom *cdxgo.BOM

			if setupMocks != nil {
				mockRepo := mock.NewMockGitRepo(gomock.NewController(GinkgoT()))
				gitRepo, commit, imageContext, bom = setupMocks(ctx, mockRepo)
			}

			result, err := ResolveUnknownVersions(ctx, bom, gitRepo, commit, imageContext)

			if expectError {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrorMsg))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}

			if verify != nil {
				verify(result, err)
			}
		},
		Entry(
			"resolves versions from git tag",
			false,
			"",
			func(ctx context.Context, gitRepo *mock.MockGitRepo) (git_repo.GitRepo, string, string, *cdxgo.BOM) {
				commit := "8d0a3fced4f1a98b6f51442e2a73c8417b8f45af"
				imageContext := "app"
				goModPath := "app/go.mod"
				goModContent := []byte("module example.com/app\n\nreplace example.com/replaced => ./local\n")

				gitRepo.EXPECT().IsCommitFileExist(ctx, commit, goModPath).Return(true, nil)
				gitRepo.EXPECT().ReadCommitFile(ctx, commit, goModPath).Return(goModContent, nil)
				gitRepo.EXPECT().TagsList(ctx).Return([]string{"v0.9.0", "v1.2.0"}, nil)
				gitRepo.EXPECT().TagCommit(ctx, "v0.9.0").Return("deadbeef", nil)
				gitRepo.EXPECT().TagCommit(ctx, "v1.2.0").Return(commit, nil)

				bom := &cdxgo.BOM{Components: &[]cdxgo.Component{{
					Name:    "example.com/app",
					Version: "UNKNOWN",
					Type:    cdxgo.ComponentTypeLibrary,
				}}}

				return gitRepo, commit, imageContext, bom
			},
			func(result *cdxgo.BOM, err error) {
				Expect((*result.Components)[0].Version).To(Equal("v1.2.0"))
			},
		),
		Entry(
			"keeps BOM unchanged when go.mod is missing",
			false,
			"",
			func(ctx context.Context, gitRepo *mock.MockGitRepo) (git_repo.GitRepo, string, string, *cdxgo.BOM) {
				commit := "8d0a3fced4f1a98b6f51442e2a73c8417b8f45af"
				imageContext := "app"
				goModPath := "app/go.mod"

				gitRepo.EXPECT().IsCommitFileExist(ctx, commit, goModPath).Return(false, nil)

				bom := &cdxgo.BOM{Components: &[]cdxgo.Component{{
					Name:    "example.com/app",
					Version: "UNKNOWN",
					Type:    cdxgo.ComponentTypeLibrary,
				}}}

				return gitRepo, commit, imageContext, bom
			},
			func(result *cdxgo.BOM, err error) {
				Expect((*result.Components)[0].Version).To(Equal("UNKNOWN"))
			},
		),
		Entry(
			"does not update non-go components",
			false,
			"",
			func(ctx context.Context, gitRepo *mock.MockGitRepo) (git_repo.GitRepo, string, string, *cdxgo.BOM) {
				commit := "8d0a3fced4f1a98b6f51442e2a73c8417b8f45af"
				imageContext := "app"
				goModPath := "app/go.mod"
				goModContent := []byte("module example.com/app\n")

				gitRepo.EXPECT().IsCommitFileExist(ctx, commit, goModPath).Return(true, nil)
				gitRepo.EXPECT().ReadCommitFile(ctx, commit, goModPath).Return(goModContent, nil)
				gitRepo.EXPECT().TagsList(ctx).Return([]string{}, nil)

				bom := &cdxgo.BOM{Components: &[]cdxgo.Component{{
					Name:    "example.com/other",
					Version: "UNKNOWN",
					Type:    cdxgo.ComponentTypeApplication,
				}}}

				return gitRepo, commit, imageContext, bom
			},
			func(result *cdxgo.BOM, err error) {
				Expect((*result.Components)[0].Version).To(Equal("UNKNOWN"))
			},
		),
		Entry(
			"returns error for non-local replace",
			true,
			"non-local replace",
			func(ctx context.Context, gitRepo *mock.MockGitRepo) (git_repo.GitRepo, string, string, *cdxgo.BOM) {
				commit := "8d0a3fced4f1a98b6f51442e2a73c8417b8f45af"
				imageContext := "app"
				goModPath := "app/go.mod"
				goModContent := []byte("module example.com/app\n\nreplace example.com/replaced => example.com/other v1.2.3\n")

				gitRepo.EXPECT().IsCommitFileExist(ctx, commit, goModPath).Return(true, nil)
				gitRepo.EXPECT().ReadCommitFile(ctx, commit, goModPath).Return(goModContent, nil)

				bom := &cdxgo.BOM{}

				return gitRepo, commit, imageContext, bom
			},
			nil,
		),
	)
})
