package checker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/docker"
	"github.com/werf/werf/v2/pkg/sbom/ispras"
)

const (
	Image         = "registry.werf.io/sbom-toolkit/3p-ispras-sbom-checker:master"
	containerPath = "/sbom/input.json"
	errorPrefix   = "ERROR:"
	warningPrefix = "WARNING:"
)

type RunOptions struct {
	CheckVCS       bool
	FailOnWarnings bool
}

func Run(ctx context.Context, paths []string, format ispras.Format, opts RunOptions) error {
	if err := checkFilesExisting(paths); err != nil {
		return err
	}

	header := fmt.Sprintf("Validating %d SBOM file(s) as %q", len(paths), format)
	if opts.CheckVCS {
		header += " with VCS check"
	}

	return logboek.Context(ctx).Default().LogProcess(header).DoError(func() error {
		logboek.Context(ctx).Debug().LogF("Using checker image: %s\n", Image)

		var failures []string
		var errCount, warningCount int
		total := len(paths)

		for i, p := range paths {
			args, err := buildDockerArgs(p, format, opts.CheckVCS)
			if err != nil {
				return fmt.Errorf("build docker args for %q: %w", p, err)
			}

			fileName := filepath.Base(p)

			out, err := docker.CliRun_RecordedOutput(ctx, args...)
			if err != nil && out == "" {
				return fmt.Errorf("run sbom-checker container for %s: %w", fileName, err)
			}

			res := parseResult(out)
			errCount += len(res.errs)
			warningCount += len(res.warnings)

			if err := res.report(ctx, fileName, i+1, total, opts.FailOnWarnings); err != nil {
				failures = append(failures, err.Error())
			}
		}

		passed := total - len(failures)
		logboek.Context(ctx).Default().LogF("Result: %d passed, %d failed; %d error(s), %d warning(s)\n", passed, len(failures), errCount, warningCount)

		if len(failures) > 0 {
			return fmt.Errorf("%s", strings.Join(failures, "\n"))
		}

		return nil
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

func buildDockerArgs(path string, format ispras.Format, checkVCS bool) ([]string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path for %q: %w", path, err)
	}

	args := []string{
		"--rm",
		"-v", absPath + ":" + containerPath + ":ro",
		Image,
		"--format", format.String(),
		"--errors", "0",
	}

	if checkVCS {
		args = append(args, "--check-vcs")
	}

	return append(args, containerPath), nil
}

type fileResult struct {
	errs     []string
	warnings []string
}

func parseResult(out string) fileResult {
	return fileResult{
		errs:     extractPrefixedLines(out, errorPrefix),
		warnings: extractPrefixedLines(out, warningPrefix),
	}
}

func (r fileResult) report(ctx context.Context, fileName string, index, total int, failOnWarnings bool) error {
	failed := len(r.errs) > 0 || (failOnWarnings && len(r.warnings) > 0)

	switch {
	case failed:
		logboek.Context(ctx).Default().LogF("(%d/%d) %s... FAILED\n", index, total, fileName)
	case len(r.warnings) > 0:
		logboek.Context(ctx).Default().LogF("(%d/%d) %s... OK (%d warning(s))\n", index, total, fileName, len(r.warnings))
	default:
		logboek.Context(ctx).Default().LogF("(%d/%d) %s... OK\n", index, total, fileName)
	}

	for _, e := range r.errs {
		logboek.Context(ctx).Default().LogF("  %s\n", e)
	}
	for _, w := range r.warnings {
		logboek.Context(ctx).Warn().LogF("  %s\n", w)
	}

	if !failed {
		return nil
	}

	details := append(append([]string{}, r.errs...), r.warnings...)

	return fmt.Errorf("validation failed for %s:\n%s", fileName, strings.Join(details, "\n"))
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
