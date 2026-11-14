package stage

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/werf/werf/v3/pkg/git_repo"
	"github.com/werf/werf/v3/pkg/werf"
)

type GitSourceFiles struct {
	Repository string
	Commit     string
	Files      map[string]string
	Symlinks   map[string]string
}

func (gm *GitMapping) SBOMSource(ctx context.Context) (GitSourceFiles, error) {
	metadata, err := gm.gitSource(ctx)
	if err != nil {
		return GitSourceFiles{}, err
	}
	opts, err := gm.makeArchiveOptions(ctx, metadata.Commit)
	if err != nil {
		return GitSourceFiles{}, err
	}
	lock, err := git_repo.CommonGitDataManager.LockGC(ctx, true)
	if err != nil {
		return GitSourceFiles{}, err
	}
	defer werf.HostLocker().ReleaseLock(lock)
	archive, err := gm.GitRepo().GetOrCreateArchive(ctx, *opts)
	if err != nil {
		return GitSourceFiles{}, fmt.Errorf("read commit archive: %w", err)
	}
	file, err := os.Open(archive.GetFilePath())
	if err != nil {
		return GitSourceFiles{}, fmt.Errorf("open commit archive: %w", err)
	}
	defer file.Close()
	directory, err := gm.GitRepo().IsCommitTreeEntryDirectory(ctx, metadata.Commit, gm.Add)
	if err != nil {
		return GitSourceFiles{}, fmt.Errorf("read git mapping type: %w", err)
	}
	result, err := gitArchiveSourceFiles(ctx, file, gm.To, directory)
	if err != nil {
		return GitSourceFiles{}, err
	}
	result.Repository, result.Commit = metadata.Source, metadata.Commit
	return result, nil
}

func gitArchiveSourceFiles(ctx context.Context, reader io.Reader, destination string, directory bool) (GitSourceFiles, error) {
	result := GitSourceFiles{Files: map[string]string{}, Symlinks: map[string]string{}}
	archive := tar.NewReader(reader)
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		header, err := archive.Next()
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return result, fmt.Errorf("read git archive: %w", err)
		}
		name := path.Clean(header.Name)
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return result, fmt.Errorf("invalid git archive path %q", header.Name)
		}
		filename := destination
		if directory {
			filename = path.Join(destination, name)
		}
		switch header.Typeflag {
		case tar.TypeReg:
			sum := sha256.New()
			if _, err := io.Copy(sum, archive); err != nil {
				return result, fmt.Errorf("hash git file %s: %w", filename, err)
			}
			result.Files[filename] = fmt.Sprintf("sha256:%x", sum.Sum(nil))
		case tar.TypeSymlink:
			result.Symlinks[filename] = header.Linkname
		case tar.TypeDir:
		default:
			return result, fmt.Errorf("%s: unsupported git archive entry type %d", filename, header.Typeflag)
		}
	}
}
