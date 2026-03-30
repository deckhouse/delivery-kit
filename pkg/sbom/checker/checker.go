package checker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/docker"
)

const (
	Image         = "localhost:5001/sbom-checker:latest"
	errorPrefix   = "ERROR:"
	warningPrefix = "WARNING:"
)

type RunOptions struct {
	CheckVCS bool
}

func Run(ctx context.Context, paths []string, isprasFormat IsprasFormat, opts RunOptions) error {
	if err := checkFilesExisting(paths); err != nil {
		return err
	}

	logboek.Context(ctx).Debug().LogF("Using checker image: %s\n", Image)

	args, err := buildDockerArgs(paths, isprasFormat, opts.CheckVCS)
	if err != nil {
		return fmt.Errorf("build docker args: %w", err)
	}

	header := fmt.Sprintf("Validating %d SBOM file(s) as %q", len(paths), isprasFormat)
	if opts.CheckVCS {
		header += " with VCS check"
	}

	return logboek.Context(ctx).Default().LogProcess(header).DoError(func() error {
		out, err := docker.CliRun_RecordedOutput(ctx, args...)
		if err != nil && out == "" {
			return fmt.Errorf("run sbom-checker container: %w", err)
		}

		passed, failed, parseErr := parseOutput(ctx, out, paths, isprasFormat)
		logboek.Context(ctx).Default().LogF("Result: %d passed, %d failed\n", passed, failed)

		return parseErr
	})
}

func checkFilesExisting(paths []string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("unable to access sbom file %q: %w", p, err)
		}
	}

	return nil
}

func buildDockerArgs(paths []string, isprasFormat IsprasFormat, checkVCS bool) ([]string, error) {
	args := []string{"--rm"}

	containerPaths := make([]string, len(paths))
	for i, p := range paths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("resolve absolute path for %q: %w", p, err)
		}
		containerPaths[i] = fmt.Sprintf("/sbom/%d.json", i)
		args = append(args, "-v", absPath+":"+containerPaths[i]+":ro")
	}

	if len(paths) == 1 {
		args = append(args, Image)
		args = append(args, checkerFlags(isprasFormat, checkVCS, containerPaths[0])...)

		return args, nil
	}

	args = append(args, "--entrypoint", "sh", Image, "-c", multiFileScript(containerPaths, isprasFormat, checkVCS))

	return args, nil
}

func checkerFlags(isprasFormat IsprasFormat, checkVCS bool, file string) []string {
	flags := []string{"--format", isprasFormat.String(), "--errors", "0"}
	if checkVCS {
		flags = append(flags, "--check-vcs")
	}

	return append(flags, file)
}

func multiFileScript(containerPaths []string, isprasFormat IsprasFormat, checkVCS bool) string {
	commands := make([]string, 0, len(containerPaths))
	for i, cp := range containerPaths {
		cmd := fmt.Sprintf("echo '===FILE:%d===' && python sbom-checker.py %s",
			i, strings.Join(checkerFlags(isprasFormat, checkVCS, cp), " "))
		commands = append(commands, cmd)
	}

	return strings.Join(commands, "; ")
}

func parseOutput(ctx context.Context, out string, paths []string, isprasFormat IsprasFormat) (int, int, error) {
	if len(paths) == 1 {
		if err := parseSingleResult(ctx, out, paths[0], isprasFormat); err != nil {
			return 0, 1, err
		}
		return 1, 0, nil
	}

	return parseMultiResult(ctx, out, paths, isprasFormat)
}

func parseSingleResult(ctx context.Context, out, path string, isprasFormat IsprasFormat) error {
	fileName := filepath.Base(path)

	errs := extractPrefixedLines(out, errorPrefix)
	warnings := extractPrefixedLines(out, warningPrefix)

	if len(errs) == 0 && len(warnings) == 0 {
		logboek.Context(ctx).Default().LogF("(1/1) %s (%s)... OK\n", fileName, isprasFormat)
		return nil
	}

	logboek.Context(ctx).Default().LogF("(1/1) %s (%s)... FAILED\n", fileName, isprasFormat)
	for _, e := range errs {
		logboek.Context(ctx).Default().LogF("  %s\n", e)
	}
	for _, w := range warnings {
		logboek.Context(ctx).Default().LogF("  %s\n", w)
	}

	return fmt.Errorf("validation failed for %s", fileName)
}

func parseMultiResult(ctx context.Context, out string, paths []string, isprasFormat IsprasFormat) (int, int, error) {
	var failures []string
	passed := 0
	total := len(paths)
	processed := 0

	sections := strings.Split(out, "===FILE:")
	for _, section := range sections[1:] {
		idx := strings.Index(section, "===")
		if idx < 0 {
			continue
		}

		indexStr := section[:idx]
		content := section[idx+3:]

		var fileName string
		var fileIdx int
		if _, err := fmt.Sscanf(indexStr, "%d", &fileIdx); err == nil && fileIdx < len(paths) {
			fileName = filepath.Base(paths[fileIdx])
		} else {
			fileName = indexStr
		}

		processed++

		errs := extractPrefixedLines(content, errorPrefix)
		warnings := extractPrefixedLines(content, warningPrefix)

		if len(errs) == 0 && len(warnings) == 0 {
			logboek.Context(ctx).Default().LogF("(%d/%d) %s (%s)... OK\n", processed, total, fileName, isprasFormat)
			passed++
			continue
		}

		logboek.Context(ctx).Default().LogF("(%d/%d) %s (%s)... FAILED\n", processed, total, fileName, isprasFormat)
		for _, e := range errs {
			logboek.Context(ctx).Default().LogF("  %s\n", e)
		}
		for _, w := range warnings {
			logboek.Context(ctx).Default().LogF("  %s\n", w)
		}

		var details []string
		details = append(details, errs...)
		details = append(details, warnings...)
		failures = append(failures, fmt.Sprintf("validation failed for %s:\n%s", fileName, strings.Join(details, "\n")))
	}

	if len(failures) > 0 {
		return passed, len(failures), fmt.Errorf("%s", strings.Join(failures, "\n"))
	}

	return passed, 0, nil
}

func extractPrefixedLines(text, prefix string) []string {
	var result []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			result = append(result, trimmed)
		}
	}

	return result
}
