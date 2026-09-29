package merge

import "github.com/werf/werf/v3/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Merge per-image CycloneDX 1.6 SBOMs into a single product/module-level SBOM.

Takes a JSON mapping file (image name -> sha256 digest) as input, pulls per-image SBOMs from the container registry, and produces an aggregated SBOM with preserved dependency graphs.

Two ISPRAS-defined output formats are supported:
- "container": hierarchical — each image becomes a top-level container component with nested packages.
- "oss": flat — all packages from all images are merged into a deduplicated flat list.

GOST properties are aggregated bottom-up: attack_surface with the "yes > indirect > no" precedence rule, security_function with "yes > no". An image SBOM carrying a GOST value outside these domains, such as security_function "indirect" written by an older werf, is rejected; rebuild the image first.

The flags --input, --ispras-format, --app-name, --app-version and --manufacturer are required. The merged SBOM is written to stdout unless --output is given.`

	docs.LongMD = "Merge per-image CycloneDX 1.6 SBOMs into a single product/module-level SBOM.\n\n" +
		"Takes a JSON mapping file (image name → sha256 digest) as input, pulls per-image SBOMs " +
		"from the container registry, and produces an aggregated SBOM with preserved dependency graphs.\n\n" +
		"Two ISPRAS-defined output formats are supported:\n" +
		"- `container`: hierarchical — each image becomes a top-level container component with nested packages.\n" +
		"- `oss`: flat — all packages from all images are merged into a deduplicated flat list.\n\n" +
		"GOST properties are aggregated bottom-up: `attack_surface` with the `yes > indirect > no` " +
		"precedence rule, `security_function` with `yes > no`. An image SBOM carrying a GOST value outside these domains, " +
		"such as `security_function: indirect` written by an older werf, is rejected; rebuild the image first.\n\n" +
		"The flags `--input`, `--ispras-format`, `--app-name`, `--app-version` and `--manufacturer` " +
		"are required. The merged SBOM is written to stdout unless `--output` is given."

	return docs
}
