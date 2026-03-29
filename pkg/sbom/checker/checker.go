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

func Run(ctx context.Context, paths []string, sbomType SbomType, opts RunOptions) error {
	if err := checkFilesExisting(paths); err != nil {
		return err
	}

	logboek.Context(ctx).Default().LogF("Validating %d SBOM file(s) as %q\n", len(paths), sbomType)
	logboek.Context(ctx).Debug().LogF("Using checker image: %s\n", Image)

	args, err := buildDockerArgs(paths, sbomType, opts.CheckVCS)
	if err != nil {
		return fmt.Errorf("build docker args: %w", err)
	}

	out, err := docker.CliRun_RecordedOutput(ctx, args...)
	if err != nil && out == "" {
		return fmt.Errorf("run sbom-checker container: %w", err)
	}

	passed, failed, parseErr := parseOutput(ctx, out, paths, sbomType)

	logboek.Context(ctx).Default().LogF("Validation complete: %d passed, %d failed\n", passed, failed)

	return parseErr
}

func checkFilesExisting(paths []string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("unable to access sbom file %q: %w", p, err)
		}
	}

	return nil
}

func buildDockerArgs(paths []string, sbomType SbomType, checkVCS bool) ([]string, error) {
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
		args = append(args, checkerFlags(sbomType, checkVCS, containerPaths[0])...)

		return args, nil
	}

	args = append(args, "--entrypoint", "sh", Image, "-c", multiFileScript(containerPaths, sbomType, checkVCS))

	return args, nil
}

func checkerFlags(sbomType SbomType, checkVCS bool, file string) []string {
	flags := []string{"--format", sbomType.String(), "--errors", "0"}
	if checkVCS {
		flags = append(flags, "--check-vcs")
	}

	return append(flags, file)
}

func multiFileScript(containerPaths []string, sbomType SbomType, checkVCS bool) string {
	commands := make([]string, 0, len(containerPaths))
	for i, cp := range containerPaths {
		cmd := fmt.Sprintf("echo '===FILE:%d===' && python sbom-checker.py %s",
			i, strings.Join(checkerFlags(sbomType, checkVCS, cp), " "))
		commands = append(commands, cmd)
	}

	return strings.Join(commands, "; ")
}

func parseOutput(ctx context.Context, out string, paths []string, sbomType SbomType) (int, int, error) {
	if len(paths) == 1 {
		if err := parseSingleResult(ctx, out, paths[0], sbomType); err != nil {
			return 0, 1, err
		}
		return 1, 0, nil
	}

	return parseMultiResult(ctx, out, paths, sbomType)
}

func parseSingleResult(ctx context.Context, out, path string, sbomType SbomType) error {
	fileName := filepath.Base(path)

	errs := extractPrefixedLines(out, errorPrefix)
	warnings := extractPrefixedLines(out, warningPrefix)

	if len(errs) == 0 && len(warnings) == 0 {
		logboek.Context(ctx).Default().LogF("Validating %s (%s)... OK\n", fileName, sbomType)
		return nil
	}

	logboek.Context(ctx).Default().LogF("Validating %s (%s)... FAILED\n", fileName, sbomType)
	for _, e := range errs {
		logboek.Context(ctx).Default().LogF("  %s\n", e)
	}
	for _, w := range warnings {
		logboek.Context(ctx).Default().LogF("  %s\n", w)
	}

	return fmt.Errorf("validation failed for %s", fileName)
}

func parseMultiResult(ctx context.Context, out string, paths []string, sbomType SbomType) (int, int, error) {
	var failures []string
	passed := 0

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

		errs := extractPrefixedLines(content, errorPrefix)
		warnings := extractPrefixedLines(content, warningPrefix)

		if len(errs) == 0 && len(warnings) == 0 {
			logboek.Context(ctx).Default().LogF("Validating %s (%s)... OK\n", fileName, sbomType)
			passed++
			continue
		}

		logboek.Context(ctx).Default().LogF("Validating %s (%s)... FAILED\n", fileName, sbomType)
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
