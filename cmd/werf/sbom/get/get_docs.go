package get

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Get SBOM of an image that is described in werf.yaml and prints the result to stdout.

SBOM is stored as an OCI artifact attached to the container image in the container registry, so --repo is required.
If SBOM is not found, the command triggers werf build to generate one.

A specific version of the image may be selected with --tag or --digest; these flags are mutually exclusive.`

	docs.LongMD = "Get SBOM of an image that is described in `werf.yaml` and prints the result to stdout.\n\n" +
		"SBOM is stored as an OCI artifact attached to the container image in the container registry, " +
		"so `--repo` is required.\n" +
		"If SBOM is not found, the command triggers werf build to generate one.\n\n" +
		"A specific version of the image may be selected with `--tag` or `--digest`; " +
		"these flags are mutually exclusive."

	return docs
}
