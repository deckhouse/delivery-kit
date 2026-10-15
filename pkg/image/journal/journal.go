package journal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const Env = "_WERF_TEST_IMAGE_JOURNAL"

var imageID = regexp.MustCompile(`^[a-f0-9]{64}$`)

var failures = struct {
	sync.Mutex
	directories map[string]error
}{directories: make(map[string]error)}

func Begin(ctx context.Context, directory string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	marker, err := os.CreateTemp(directory, "pending-")
	if err != nil {
		return nil, fmt.Errorf("begin image journal: %w", err)
	}
	if err := marker.Close(); err != nil {
		return nil, fmt.Errorf("close image journal marker: %w", err)
	}
	return func() error {
		failures.Lock()
		err := failures.directories[directory]
		failures.Unlock()
		if err != nil {
			return err
		}
		if err := os.Remove(marker.Name()); err != nil {
			return fmt.Errorf("finish image journal: %w", err)
		}
		return nil
	}, nil
}

func Check(ctx context.Context, directory string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("check image journal: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || (entry.Name() != "docker" && entry.Name() != "buildah") {
			return fmt.Errorf("incomplete image journal: %q", entry.Name())
		}
	}
	return nil
}

func Record(ctx context.Context, directory, id string) error {
	err := record(ctx, directory, id)
	if err != nil {
		failures.Lock()
		failures.directories[filepath.Dir(directory)] = err
		failures.Unlock()
	}
	return err
}

func record(ctx context.Context, directory, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id = strings.TrimPrefix(id, "sha256:")
	if !imageID.MatchString(id) {
		return fmt.Errorf("invalid journal image ID %q", id)
	}
	file, err := os.OpenFile(filepath.Join(directory, id), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open image journal record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close image journal record: %w", err)
	}
	return nil
}

func Read(ctx context.Context, directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read image journal: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !imageID.MatchString(entry.Name()) || entry.Type() != 0 {
			return nil, fmt.Errorf("invalid image journal entry %q", entry.Name())
		}
		ids = append(ids, entry.Name())
	}
	return ids, nil
}
