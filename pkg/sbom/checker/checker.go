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
	CheckVCS                bool
	CheckVCSLeafOnly        bool
	CheckSourceDistribution bool
}

// Validate rejects option combinations the checker image does not honor.
// Its --check-vcs-leaf-only skips a non-leaf component before any of its
// external references is read, so combined with --check-source-distribution
// the archives of every non-leaf component go unchecked while the run reports
// success.
func (opts RunOptions) Validate() error {
	if opts.CheckVCSLeafOnly && opts.CheckSourceDistribution {
		return fmt.Errorf("--check-vcs-leaf-only cannot be combined with --check-source-distribution: the checker would skip source distributions of non-leaf components; use --check-vcs instead")
	}

	return nil
}

func Run(ctx context.Context, paths []string, format ispras.Format, opts RunOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	if err := checkFilesExisting(paths); err != nil {
		return err
	}

	header := fmt.Sprintf("Validating %d SBOM file(s) as %q", len(paths), format)
	if checks := enabledChecks(opts); len(checks) > 0 {
		header += fmt.Sprintf(" with %s check", strings.Join(checks, ", "))
	}

	return logboek.Context(ctx).Default().LogProcess(header).DoError(func() error {
		logboek.Context(ctx).Debug().LogF("Using checker image: %s\n", Image)

		var failures []string
		total := len(paths)

		for i, p := range paths {
			args, err := buildDockerArgs(p, format, opts)
			if err != nil {
				return fmt.Errorf("build docker args for %q: %w", p, err)
			}

			fileName := filepath.Base(p)

			out, err := docker.CliRun_RecordedOutput(ctx, args...)
			if err != nil && out == "" {
				return fmt.Errorf("run sbom-checker container for %s: %w", fileName, err)
			}

			if err := parseResult(ctx, out, fileName, i+1, total); err != nil {
				failures = append(failures, err.Error())
			}
		}

		passed := total - len(failures)
		logboek.Context(ctx).Default().LogF("Result: %d passed, %d failed\n", passed, len(failures))

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

func buildDockerArgs(path string, format ispras.Format, opts RunOptions) ([]string, error) {
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

	if opts.CheckVCS {
		args = append(args, "--check-vcs")
	}

	if opts.CheckVCSLeafOnly {
		args = append(args, "--check-vcs-leaf-only")
	}

	if opts.CheckSourceDistribution {
		args = append(args, "--check-source-distribution")
	}

	return append(args, containerPath), nil
}

// enabledChecks names what the checker image really runs: --check-source-distribution
// turns on the VCS URL check of every component as well, and --check-vcs-leaf-only
// narrows a VCS check to leaf components.
func enabledChecks(opts RunOptions) []string {
	var checks []string
	switch {
	case opts.CheckVCSLeafOnly:
		checks = append(checks, "leaf-only VCS")
	case opts.CheckVCS || opts.CheckSourceDistribution:
		checks = append(checks, "VCS")
	}
	if opts.CheckSourceDistribution {
		checks = append(checks, "source distribution")
	}
	return checks
}

func parseResult(ctx context.Context, out, fileName string, index, total int) error {
	errs := extractPrefixedLines(out, errorPrefix)
	warnings := extractPrefixedLines(out, warningPrefix)

	if len(errs) == 0 && len(warnings) == 0 {
		logboek.Context(ctx).Default().LogF("(%d/%d) %s... OK\n", index, total, fileName)
		return nil
	}

	logboek.Context(ctx).Default().LogF("(%d/%d) %s... FAILED\n", index, total, fileName)
	for _, e := range errs {
		logboek.Context(ctx).Default().LogF("  %s\n", e)
	}
	for _, w := range warnings {
		logboek.Context(ctx).Default().LogF("  %s\n", w)
	}

	var details []string
	details = append(details, errs...)
	details = append(details, warnings...)

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
