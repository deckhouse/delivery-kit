//go:build linux

package contback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/onsi/ginkgo/v2"
	"go.podman.io/common/libimage"
	"go.podman.io/storage"
	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"

	"github.com/werf/werf/v3/pkg/buildah"
	"github.com/werf/werf/v3/pkg/image/journal"
)

const cleanupProjectEnv = "_WERF_TEST_CLEANUP_PROJECT"

type cleanupProjectRequest struct {
	ProjectName  string
	Repositories []string
	ImageIDs     []string
}

func init() {
	if reexec.Init() {
		os.Exit(0)
	}
	requestJSON, requested := os.LookupEnv(cleanupProjectEnv)
	if !requested {
		return
	}
	if err := os.Unsetenv(cleanupProjectEnv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var request cleanupProjectRequest
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	err := cleanupBuildahProjectInNamespace(ctx, request)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func cleanupBuildahProject(ctx context.Context, projectName string, repos []string) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find test executable: %w", err)
	}
	cleanupRequest := cleanupProjectRequest{ProjectName: projectName, Repositories: repos}
	if directory := os.Getenv(journal.Env); directory != "" {
		cleanupRequest.ImageIDs, err = journal.Read(ctx, filepath.Join(directory, "buildah"))
		if err != nil {
			return err
		}
	}
	request, err := json.Marshal(cleanupRequest)
	if err != nil {
		return fmt.Errorf("encode cleanup request: %w", err)
	}
	command := exec.CommandContext(ctx, "buildah", "unshare", executable)
	if os.Geteuid() == 0 {
		command = exec.CommandContext(ctx, executable)
	}
	command.Env = append(os.Environ(), cleanupProjectEnv+"="+string(request))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	var output bytes.Buffer
	writer := io.MultiWriter(&output, ginkgo.GinkgoWriter)
	command.Stdout, command.Stderr = writer, writer
	done := traceBuildahCleanupPhase(ginkgo.GinkgoWriter, projectName, "worker process")
	err = command.Run()
	done(err)
	if err != nil {
		return fmt.Errorf("clean buildah project images: %w: %s", err, output.String())
	}
	return nil
}

func cleanupBuildahProjectInNamespace(ctx context.Context, request cleanupProjectRequest) error {
	if request.ProjectName == "" {
		return fmt.Errorf("empty test project")
	}
	done := traceBuildahCleanupPhase(os.Stderr, request.ProjectName, "storage options")
	options, err := buildah.NewNativeStoreOptions(unshare.GetRootlessUID(), buildah.DefaultStorageDriver)
	done(err)
	if err != nil {
		return fmt.Errorf("get test storage options: %w", err)
	}
	done = traceBuildahCleanupPhase(os.Stderr, request.ProjectName, "open storage")
	store, err := storage.GetStore(storage.StoreOptions(*options))
	done(err)
	if err != nil {
		return fmt.Errorf("open test image storage: %w", err)
	}
	store = &cleanupTraceStore{Store: store, writer: os.Stderr, projectName: request.ProjectName}
	done = traceBuildahCleanupPhase(os.Stderr, request.ProjectName, "open image runtime")
	imageRuntime, err := libimage.RuntimeFromStore(store, &libimage.RuntimeOptions{})
	done(err)
	if err != nil {
		return fmt.Errorf("open test image runtime: %w", err)
	}
	return cleanupBuildahProjectImages(ctx, request, store, imageRuntime)
}

func cleanupBuildahProjectImages(ctx context.Context, request cleanupProjectRequest, store storage.Store, imageRuntime *libimage.Runtime) error {
	pass := 0
	var candidates []cleanupImage
	idsByReference := make(map[string]string)
	var removalErrors []error
	for _, id := range request.ImageIDs {
		candidates = append(candidates, cleanupImage{ID: id})
	}
	list := func() ([]string, error) {
		pass++
		var selected []cleanupImage
		if pass == 1 && request.ImageIDs == nil {
			done := traceBuildahCleanupPhase(os.Stderr, request.ProjectName, fmt.Sprintf("list pass=%d", pass))
			images, err := imageRuntime.ListImages(ctx, &libimage.ListImagesOptions{Filters: []string{"label=werf=" + request.ProjectName}})
			done(err)
			if err != nil {
				return nil, fmt.Errorf("list native test images: %w", err)
			}
			for _, img := range images {
				selected = append(selected, cleanupImage{ID: img.ID(), Names: img.Names()})
			}
		} else {
			done := traceBuildahCleanupPhase(os.Stderr, request.ProjectName, fmt.Sprintf("refresh pass=%d", pass))
			for _, candidate := range candidates {
				if err := ctx.Err(); err != nil {
					done(err)
					return nil, err
				}
				image, err := store.Image(candidate.ID)
				if errors.Is(err, storage.ErrImageUnknown) {
					continue
				}
				if err != nil {
					done(err)
					return nil, fmt.Errorf("refresh native test image %q: %w", candidate.ID, err)
				}
				if pass == 1 {
					resolved, _, err := imageRuntime.LookupImage(image.ID, nil)
					if err != nil {
						done(err)
						return nil, fmt.Errorf("resolve journal image %q: %w", image.ID, err)
					}
					labels, err := resolved.Labels(ctx)
					if err != nil {
						done(err)
						return nil, fmt.Errorf("read journal image ownership %q: %w", image.ID, err)
					}
					if labels["werf"] != request.ProjectName {
						continue
					}
				}
				selected = append(selected, cleanupImage{ID: image.ID, Names: image.Names})
			}
			done(nil)
		}
		candidates = selected
		clear(idsByReference)
		for _, image := range selected {
			for _, ref := range projectImageReferences([]cleanupImage{image}, request.ProjectName, request.Repositories) {
				idsByReference[ref] = image.ID
			}
		}
		references := projectImageReferences(selected, request.ProjectName, request.Repositories)
		fmt.Fprintf(os.Stderr, "[buildah cleanup] project=%q pass=%d images=%d references=%d\n", request.ProjectName, pass, len(selected), len(references))
		return references, nil
	}
	removeImage := func(ctx context.Context, ref string) error {
		done := traceBuildahCleanupPhase(os.Stderr, request.ProjectName, fmt.Sprintf("remove pass=%d ref=%q", pass, ref))
		id, known := idsByReference[ref]
		if !known {
			err := fmt.Errorf("unknown native cleanup reference %q", ref)
			done(err)
			return err
		}
		err := removeNativeCleanupImage(ctx, store, id, ref)
		done(err)
		if errors.Is(err, storage.ErrImageUsedByContainer) {
			return errors.Join(errCleanupImageInUse, err)
		}
		if err != nil {
			removalErrors = append(removalErrors, err)
		}
		return err
	}
	cleanupErr := cleanupImageReferences(ctx, "buildah", list, removeImage)
	return errors.Join(cleanupErr, errors.Join(removalErrors...))
}

func removeNativeCleanupImage(ctx context.Context, store storage.Store, id, ref string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	image, err := store.Image(id)
	if errors.Is(err, storage.ErrImageUnknown) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read native cleanup image %q: %w", id, err)
	}
	if image.ReadOnly {
		return fmt.Errorf("refuse cleanup of read-only image %q", id)
	}
	if len(image.Names) > 0 {
		if !slices.Contains(image.Names, ref) {
			return nil
		}
		if len(image.Names) > 1 {
			if err := store.RemoveNames(id, []string{ref}); err != nil {
				return fmt.Errorf("remove native image name %q: %w", ref, err)
			}
			return nil
		}
	}
	_, err = store.DeleteImage(id, true)
	if err != nil {
		return fmt.Errorf("delete native cleanup image %q: %w", id, err)
	}
	return nil
}

func traceBuildahCleanupPhase(writer io.Writer, projectName, phase string) func(error) {
	started := time.Now()
	fmt.Fprintf(writer, "[buildah cleanup] time=%s project=%q pid=%d phase=%q event=start\n", started.UTC().Format(time.RFC3339Nano), projectName, os.Getpid(), phase)
	return func(err error) {
		fmt.Fprintf(writer, "[buildah cleanup] time=%s project=%q pid=%d phase=%q event=done elapsed=%s error=%v\n", time.Now().UTC().Format(time.RFC3339Nano), projectName, os.Getpid(), phase, time.Since(started).Round(time.Millisecond), err)
	}
}
