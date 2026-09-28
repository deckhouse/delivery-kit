package validate

import "github.com/werf/werf/v3/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Validate CycloneDX JSON SBOM files against ISPRAS schemas using sbom-checker.

The command runs sbom-checker inside a Docker container and reports validation results. Supports both OSS and container SBOM types.

The flags --path and --ispras-format are required. Repeat --path to validate several files in one run. Use --errors to cap how many schema and container-format errors are printed per file (0 means unlimited); the checker may print one extra container-format error past the cap, and VCS and source distribution findings are never capped. Pass --check-vcs or --check-vcs-leaf-only to additionally validate VCS URLs, and --check-source-distribution to check that source distribution URLs exist and point to an archive. --check-source-distribution also validates VCS URLs of every component and cannot be combined with --check-vcs-leaf-only. Pass --checker-verbose to print the full checker output for every file, including the git/svn/hg/fossil diagnostics behind each VCS or source distribution failure; it does not change werf's own log verbosity.`

	docs.LongMD = "Validate CycloneDX JSON SBOM files against ISPRAS schemas using sbom-checker.\n\n" +
		"The command runs sbom-checker inside a Docker container and reports validation results. " +
		"Supports both OSS and container SBOM types.\n\n" +
		"The flags `--path` and `--ispras-format` are required. Repeat `--path` to validate several " +
		"files in one run. Use `--errors` to cap how many schema and container-format errors are printed per file (0 means unlimited); " +
		"the checker may print one extra container-format error past the cap, and VCS and source distribution findings are never capped. " +
		"Pass `--check-vcs` or `--check-vcs-leaf-only` to additionally validate VCS URLs, " +
		"and `--check-source-distribution` to check that source distribution URLs exist and point to an archive. " +
		"`--check-source-distribution` also validates VCS URLs of every component and cannot be combined with `--check-vcs-leaf-only`. " +
		"Pass `--checker-verbose` to print the full checker output for every file, including the git/svn/hg/fossil diagnostics behind each VCS or source distribution failure; " +
		"it does not change werf's own log verbosity."

	return docs
}
