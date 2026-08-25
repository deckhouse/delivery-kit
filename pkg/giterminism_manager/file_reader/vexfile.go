package file_reader

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/werf/logboek"
)

func (r FileReader) ReadVEXFile(ctx context.Context, relPath string) (data []byte, err error) {
	logboek.Context(ctx).Debug().
		LogBlock("ReadVEXFile %q", relPath).
		Options(applyDebugToLogboek).
		Do(func() {
			data, err = r.readVEXFile(ctx, relPath)

			if debug() {
				logboek.Context(ctx).Debug().LogF("dataLength: %d\nerr: %q\n", len(data), err)
			}
		})

	if err != nil {
		return nil, fmt.Errorf("unable to read VEX file %q: %w", filepath.ToSlash(relPath), err)
	}

	return data, nil
}

func (r FileReader) readVEXFile(ctx context.Context, relPath string) ([]byte, error) {
	return r.ReadAndCheckConfigurationFile(ctx, relPath, func(path string) bool {
		return r.giterminismConfig.IsUncommittedConfigAccepted()
	}, func(path string) (bool, error) {
		return r.IsRegularFileExist(ctx, path)
	})
}
