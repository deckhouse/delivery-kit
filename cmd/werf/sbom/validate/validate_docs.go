package validate

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Validate CycloneDX JSON SBOM files against ISPRAS schemas using sbom-checker.

The command runs sbom-checker inside a Docker container and reports validation results. Supports both OSS and container SBOM types.

The flags --path and --ispras-format are required. Repeat --path to validate several files in one run. Pass --check-vcs to additionally validate VCS URLs.

Checker findings are reported separately as errors and warnings, and the summary shows both counts. By default any error or warning fails validation. Pass --warnings-non-fatal to keep warnings informational: they are still printed (on stderr), but only errors set a non-zero exit code.`

	docs.LongMD = "Validate CycloneDX JSON SBOM files against ISPRAS schemas using sbom-checker.\n\n" +
		"The command runs sbom-checker inside a Docker container and reports validation results. " +
		"Supports both OSS and container SBOM types.\n\n" +
		"The flags `--path` and `--ispras-format` are required. Repeat `--path` to validate several " +
		"files in one run. Pass `--check-vcs` to additionally validate VCS URLs.\n\n" +
		"Checker findings are reported separately as errors and warnings, and the summary shows both counts. " +
		"By default any error or warning fails validation. Pass `--warnings-non-fatal` to keep warnings " +
		"informational: they are still printed (on stderr), but only errors set a non-zero exit code."

	return docs
}
