package jsobserver

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// InstrumentationVersion identifies the embedded observer. Stages it runs in
	// include it in their digest, so it must change whenever the assets change.
	InstrumentationVersion = "1"
	BootstrapFileName      = "bootstrap.cjs"
	// MaxEventBytes bounds one JSONL record of LogPath, newline included.
	MaxEventBytes = 1 << 20
)

//go:embed assets/*.cjs
var assets embed.FS

type assetSettings struct {
	LogPath         string `json:"logPath"`
	ProtocolVersion int    `json:"protocolVersion"`
	MaxEventBytes   int    `json:"maxEventBytes"`
}

// WriteAssets writes the observer preloaded with NODE_OPTIONS into the existing
// directory dir, readable by any user of a container it is mounted into.
func WriteAssets(ctx context.Context, dir string) error {
	return writeAssets(ctx, dir, LogPath)
}

func writeAssets(ctx context.Context, dir, logPath string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write JavaScript observer assets: %w", err)
	}

	files := map[string][]byte{}
	if err := fs.WalkDir(assets, "assets", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		files[entry.Name()] = data
		return nil
	}); err != nil {
		return fmt.Errorf("read embedded JavaScript observer assets: %w", err)
	}

	settings, err := json.Marshal(assetSettings{LogPath: logPath, ProtocolVersion: ProtocolVersion, MaxEventBytes: MaxEventBytes})
	if err != nil {
		return fmt.Errorf("encode JavaScript observer settings: %w", err)
	}
	files["settings.json"] = settings

	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		// os.WriteFile applies the umask, and non-root container users must still read the file.
		if err := os.Chmod(path, 0o644); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
	}

	return nil
}
