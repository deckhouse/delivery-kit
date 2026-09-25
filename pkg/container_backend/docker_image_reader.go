package container_backend

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/uuid"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/docker"
)

var _ ImageReader = (*dockerImageReader)(nil)

// dockerImageReader reads paths out of one throwaway container via `docker cp`. The
// container is created once in OpenImageReader and removed in Close, so a caller that
// needs many paths from the same image pays for container creation a single time.
type dockerImageReader struct {
	imageRef      string
	containerName string
}

func (backend *DockerServerBackend) OpenImageReader(ctx context.Context, imageRef string, opts ReadFileFromImageOpts) (ImageReader, error) {
	containerName := fmt.Sprintf("werf.read_file.%s", uuid.New().String())

	args := []string{"--name", containerName, "--entrypoint", ""}
	if opts.TargetPlatform != "" {
		args = append(args, "--platform", opts.TargetPlatform)
	}
	args = append(args, imageRef, "werf-read-file-from-image-placeholder")

	if err := docker.CliCreate(ctx, args...); err != nil {
		return nil, fmt.Errorf("create container from image %q: %w", imageRef, err)
	}

	return &dockerImageReader{imageRef: imageRef, containerName: containerName}, nil
}

func (backend *DockerServerBackend) ReadFileFromImage(ctx context.Context, imageRef, path string, opts ReadFileFromImageOpts) ([]byte, error) {
	reader, err := backend.OpenImageReader(ctx, imageRef, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := reader.Close(ctx); err != nil {
			logboek.Context(ctx).Warn().LogF("WARNING: %s\n", err)
		}
	}()

	return reader.ReadFile(ctx, path)
}

func (r *dockerImageReader) Close(ctx context.Context) error {
	if err := docker.CliRm(ctx, "--force", r.containerName); err != nil {
		return fmt.Errorf("remove container %q: %w", r.containerName, err)
	}
	return nil
}

func (r *dockerImageReader) ReadFile(ctx context.Context, path string) ([]byte, error) {
	var data []byte
	found := false

	err := r.copy(ctx, path, func(tr *tar.Reader, hdr *tar.Header) error {
		if found || hdr.Typeflag != tar.TypeReg {
			return nil
		}
		var err error
		if data, err = io.ReadAll(tr); err != nil {
			return fmt.Errorf("read %s content from image %q: %w", path, r.imageRef, err)
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("no regular file at %s in image %q: %w", path, r.imageRef, fs.ErrNotExist)
	}

	return data, nil
}

func (r *dockerImageReader) ReadDir(ctx context.Context, path, destDir string, opts ReadDirOpts) error {
	extractor := newDirTarExtractor(path, destDir, opts.FileNamePatterns)
	if err := r.copy(ctx, path, extractor.extract); err != nil {
		return err
	}
	return extractor.resolveSymlinks()
}

// copy streams `docker cp` of path out of the container and hands every tar entry to
// visit. A missing path is reported as fs.ErrNotExist.
func (r *dockerImageReader) copy(ctx context.Context, path string, visit func(tr *tar.Reader, hdr *tar.Header) error) error {
	reader, err := docker.ContainerCopyFrom(ctx, r.containerName, path)
	if client.IsErrNotFound(err) {
		return fmt.Errorf("copy %s from image %q: %w", path, r.imageRef, fs.ErrNotExist)
	}
	if err != nil {
		return fmt.Errorf("copy %s from image %q: %w", path, r.imageRef, err)
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s tar stream from image %q: %w", path, r.imageRef, err)
		}
		if err := visit(tr, hdr); err != nil {
			return err
		}
	}
}

// dirTarExtractor writes a `docker cp <dir>` tar stream under destDir, keeping the layout
// relative to the copied directory. Only regular files are written, filtered by base name
// when patterns are set. Symlinks to directories inside the tree (pnpm lays out
// node_modules/<pkg> -> .pnpm/<pkg>@<ver>/node_modules/<pkg>) are resolved after the
// stream ends by copying the already extracted target files under the link path, so the
// result reads like the image filesystem does through the link.
type dirTarExtractor struct {
	srcDir   string
	prefix   string
	destDir  string
	patterns []string
	symlinks map[string]string
}

func newDirTarExtractor(srcDir, destDir string, patterns []string) *dirTarExtractor {
	return &dirTarExtractor{
		srcDir: srcDir,
		// docker cp of a directory yields entries prefixed with the directory's base name.
		prefix:   filepath.Base(srcDir) + "/",
		destDir:  destDir,
		patterns: patterns,
		symlinks: map[string]string{},
	}
}

// rebase maps a tar entry name onto destDir. Cleaning under an anchored root means a
// crafted entry cannot escape destDir.
func (e *dirTarExtractor) rebase(name string) string {
	rel := strings.TrimPrefix(name, e.prefix)
	return filepath.Join(e.destDir, filepath.Clean("/"+rel))
}

func (e *dirTarExtractor) extract(tr *tar.Reader, hdr *tar.Header) error {
	switch hdr.Typeflag {
	case tar.TypeSymlink:
		// A link target must be expressed relative to the copied directory, because that is
		// how the extracted files are laid out under destDir. A relative Linkname is relative
		// to the link's own directory; an absolute one is relativized against the in-image
		// source directory. Either form may point outside the copied directory, and such a
		// link is dropped: its target was not extracted, and anchoring the cleaned path
		// under destDir would silently substitute an unrelated in-tree directory.
		var target string
		if filepath.IsAbs(hdr.Linkname) {
			rel, err := filepath.Rel(e.srcDir, hdr.Linkname)
			if err != nil {
				return fmt.Errorf("relativize symlink target %q: %w", hdr.Linkname, err)
			}
			target = rel
		} else {
			linkRel := strings.TrimPrefix(hdr.Name, e.prefix)
			target = filepath.Join(filepath.Dir(linkRel), hdr.Linkname)
		}
		if target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
			return nil
		}
		e.symlinks[e.rebase(hdr.Name)] = filepath.Join(e.destDir, filepath.Clean("/"+target))
		return nil
	case tar.TypeReg:
	default:
		return nil
	}

	if !matchesAnyFileNamePattern(filepath.Base(hdr.Name), e.patterns) {
		return nil
	}

	destPath := e.rebase(hdr.Name)
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(destPath), err)
	}
	file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	if _, err := io.Copy(file, tr); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	return file.Close()
}

// resolveSymlinks materializes each recorded symlink whose target is an extracted
// directory by copying the target's files under the link path. Links are resolved on the
// recorded link set alone, expanding a recorded link found in any path component of the
// target (not only an exact match) and keeping the remaining suffix, so a chain or a link
// through a linked parent resolves regardless of the order links were recorded in and
// without depending on directories earlier iterations materialized. A cycle, a link to a
// file, to nothing, or to a path outside destDir is left out.
func (e *dirTarExtractor) resolveSymlinks() error {
	for linkPath := range e.symlinks {
		target, ok := e.resolveTarget(linkPath)
		if !ok {
			continue
		}
		err := filepath.WalkDir(target, func(srcPath string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			rel, err := filepath.Rel(target, srcPath)
			if err != nil {
				return err
			}
			destPath := filepath.Join(linkPath, rel)
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return err
			}
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return err
			}
			return os.WriteFile(destPath, data, 0o644)
		})
		if err != nil {
			return fmt.Errorf("resolve symlink %s -> %s: %w", linkPath, target, err)
		}
	}
	return nil
}

// resolveTarget expands linkPath's target until no path component of it is a recorded
// link, and reports the result if it is an extracted directory. Each expansion replaces
// the longest recorded-link prefix with that link's target and re-appends the suffix, so
// alias/is-number with alias -> .store becomes .store/is-number. Expansions are bounded
// by the number of recorded links: a cycle cannot make progress past that and is dropped.
func (e *dirTarExtractor) resolveTarget(linkPath string) (string, bool) {
	target := e.symlinks[linkPath]
	for range len(e.symlinks) {
		prefix, rest, found := e.longestLinkPrefix(target)
		if !found {
			break
		}
		target = filepath.Join(e.symlinks[prefix], rest)
	}
	if _, _, stillLinked := e.longestLinkPrefix(target); stillLinked {
		return "", false
	}
	if !strings.HasPrefix(target, e.destDir+string(filepath.Separator)) {
		return "", false
	}

	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return target, true
}

// longestLinkPrefix finds the longest recorded link that is p itself or one of its parent
// directories, returning that link and the path remainder below it.
func (e *dirTarExtractor) longestLinkPrefix(p string) (prefix, rest string, found bool) {
	for cur := p; ; cur = filepath.Dir(cur) {
		if _, isLink := e.symlinks[cur]; isLink {
			rel, err := filepath.Rel(cur, p)
			if err != nil {
				return "", "", false
			}
			return cur, rel, true
		}
		if cur == e.destDir || cur == filepath.Dir(cur) {
			return "", "", false
		}
	}
}

// matchesAnyFileNamePattern reports whether name matches one of the shell patterns,
// case-insensitively. No patterns means everything matches.
func matchesAnyFileNamePattern(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	lower := strings.ToLower(name)
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(strings.ToLower(pattern), lower); ok {
			return true
		}
	}
	return false
}
