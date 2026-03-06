package gomod

import (
	"context"
	"fmt"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/git_repo"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

func ResolveUnknownVersions(ctx context.Context, bom *cdx.BOM, gitRepo git_repo.GitRepo, commit, imageContext string) (*cdx.BOM, error) {
	if gitRepo == nil || commit == "" {
		return bom, nil
	}

	goModPath := filepath.Join(imageContext, "go.mod")

	exists, err := gitRepo.IsCommitFileExist(ctx, commit, goModPath)
	if err != nil {
		return nil, fmt.Errorf("check go.mod existence: %w", err)
	}
	if !exists {
		logboek.Context(ctx).Warn().LogF("No go.mod found at %s, skipping version resolution\n", goModPath)
		return bom, nil
	}

	content, err := gitRepo.ReadCommitFile(ctx, commit, goModPath)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	if len(content) == 0 {
		return bom, nil
	}

	info, err := ParseLocalReplaces(content)
	if err != nil {
		return nil, err
	}

	tags, err := gitRepo.TagsList(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	version, err := ResolveVersionFromTags(tags, func(tag string) (string, error) {
		return gitRepo.TagCommit(ctx, tag)
	}, commit)
	if err != nil {
		return nil, err
	}

	return cyclonedxutil.ResolveUnknownGoVersions(bom, version, info.ModulePath, info.LocalReplaceTargets), nil
}
